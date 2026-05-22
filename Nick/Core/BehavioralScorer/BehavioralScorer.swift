// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import CoreML
import os

// MARK: - BehavioralScorerError

/// Errors thrown by `BehavioralScorer`.
enum BehavioralScorerError: LocalizedError {
    /// The CoreML model file was not found in the app bundle.
    case modelNotFound
    /// CoreML model failed to load.
    case modelLoadFailed(underlying: Error)
    /// Inference failed due to a prediction error.
    case inferenceFailed(underlying: Error)
    /// The model output was malformed or missing the expected output key.
    case unexpectedOutput

    var errorDescription: String? {
        switch self {
        case .modelNotFound:
            return "ThreatScorer.mlmodel not found in app bundle. Run the training pipeline first."
        case .modelLoadFailed(let error):
            return "Failed to load ThreatScorer model: \(error.localizedDescription)"
        case .inferenceFailed(let error):
            return "CoreML inference failed: \(error.localizedDescription)"
        case .unexpectedOutput:
            return "CoreML model returned unexpected output format."
        }
    }
}

// MARK: - BehavioralScorer

/// On-device CoreML behavioral threat scorer.
///
/// `BehavioralScorer` wraps the auto-generated `ThreatScorer` CoreML class and
/// provides a clean Swift API for scoring 40-dimensional `FeatureVector` inputs.
/// It returns a normalized threat probability (0.0 = benign, 1.0 = malicious)
/// and optionally the top contributing features for explainability.
///
/// The model is loaded lazily on first use and cached for the app lifetime.
/// If the model file is absent (e.g., during tests without the `.mlmodel`),
/// `isModelAvailable` returns `false` and callers should use the rule-based fallback.
///
/// - Note: Inference is synchronous and fast (< 5ms). Do not call on the main thread
///         if latency is a concern.
final class BehavioralScorer: Sendable {

    // MARK: - Private State

    private let modelURL: URL?
    private static let logger = Logger(subsystem: "com.ehsanazish.nick", category: "BehavioralScorer")

    // MARK: - Init

    /// Creates a scorer that loads the model from the default bundle location.
    init() {
        modelURL = Bundle.main.url(forResource: "ThreatScorer", withExtension: "mlmodelc")
            ?? Bundle.main.url(forResource: "ThreatScorer", withExtension: "mlmodel")
    }

    /// Creates a scorer that loads the model from an explicit URL. Used for testing.
    init(modelURL: URL?) {
        self.modelURL = modelURL
    }

    // MARK: - Public API

    /// Whether the CoreML model is available in the app bundle.
    ///
    /// If `false`, callers must use the rule-based fallback in `ThreatCorrelator`.
    var isModelAvailable: Bool { modelURL != nil }

    /// Scores a feature vector and returns a threat probability in [0, 1].
    ///
    /// - Parameter features: The 40-dimensional feature vector to score.
    /// - Returns: Threat probability: 0.0 = benign, 1.0 = malicious.
    ///
    /// - Throws: `BehavioralScorerError.modelNotFound` if no model is in the bundle.
    ///           `BehavioralScorerError.inferenceFailed` if prediction fails.
    func score(features: FeatureVector) throws -> Double {
        let result = try predict(features: features)
        return result.threatProbability
    }

    /// Scores a feature vector and returns the top contributing features for explainability.
    ///
    /// Feature contributions are approximated using the per-feature values and their
    /// deviation from the benign baseline (all zeros). This provides a ranked list
    /// of which features had the most impact on the score.
    ///
    /// - Parameter features: The 40-dimensional feature vector to score.
    /// - Returns: Tuple of (score, top 5 feature contributions) ranked by absolute contribution.
    ///
    /// - Throws: Same errors as `score(features:)`.
    func scoreWithExplanation(features: FeatureVector) throws -> (score: Double, topFeatures: [(name: String, contribution: Double)]) {
        let result = try predict(features: features)

        // Approximate feature contributions: feature_value * score_weight
        // The score itself weights how much each feature deviates from baseline (0)
        let featureValues = features.asArray
        let names = FeatureVector.featureNames

        // Use a simple heuristic: normalize each feature's absolute value and scale
        // by the threat probability. Features that are "on" (non-zero) and the model
        // scored high contribute more. This is an approximation; a full Shapley
        // explanation would require GBT tree traversal.
        let rawContributions: [(name: String, contribution: Double)] = zip(names, featureValues).map { name, value in
            let contribution = abs(value) * result.threatProbability
            return (name: name, contribution: contribution)
        }

        let topFeatures = rawContributions
            .sorted { $0.contribution > $1.contribution }
            .prefix(5)
            .map { $0 }

        return (score: result.threatProbability, topFeatures: topFeatures)
    }

    // MARK: - Internal Helpers

    /// Performs the actual CoreML prediction.
    ///
    /// - Note: Loads the model lazily on each call (model is cached internally by CoreML).
    ///         Separate `load()` call not required.
    private func predict(features: FeatureVector) throws -> ScoringResult {
        guard let url = modelURL else {
            throw BehavioralScorerError.modelNotFound
        }

        let model: MLModel
        do {
            let config = MLModelConfiguration()
            config.computeUnits = .cpuOnly  // Deterministic, low latency for inference
            model = try MLModel(contentsOf: url, configuration: config)
        } catch {
            throw BehavioralScorerError.modelLoadFailed(underlying: error)
        }

        // Build the input feature provider from the flat Double array
        let inputDict = Dictionary(
            uniqueKeysWithValues: zip(FeatureVector.featureNames, features.asArray).map {
                ($0.0, MLFeatureValue(double: $0.1))
            }
        )

        let inputProvider: MLFeatureProvider
        do {
            inputProvider = try MLDictionaryFeatureProvider(dictionary: inputDict)
        } catch {
            throw BehavioralScorerError.inferenceFailed(underlying: error)
        }

        let outputProvider: MLFeatureProvider
        do {
            outputProvider = try model.prediction(from: inputProvider)
        } catch {
            throw BehavioralScorerError.inferenceFailed(underlying: error)
        }

        return extractResult(from: outputProvider)
    }

    /// Extracts the threat probability from the CoreML output feature provider.
    ///
    /// Supports two output formats:
    /// 1. `threatLabelProbability` dict — GBT classifier probability output
    /// 2. `threatProbability` double — direct regression output
    private func extractResult(from output: MLFeatureProvider) -> ScoringResult {
        // Try probability dictionary first (GBT classifier output from coremltools)
        if let probDict = output.featureValue(for: "threatLabelProbability")?.dictionaryValue as? [String: NSNumber] {
            let maliciousProb = probDict["2"]?.doubleValue ?? probDict["malicious"]?.doubleValue ?? 0
            let suspiciousProb = probDict["1"]?.doubleValue ?? probDict["suspicious"]?.doubleValue ?? 0
            // Weight: malicious = 1.0, suspicious = 0.5
            let score = min(1.0, maliciousProb + suspiciousProb * 0.5)
            Self.logger.debug("Scored via probabilityDict: malicious=\(maliciousProb) suspicious=\(suspiciousProb) → \(score)")
            return ScoringResult(threatProbability: score)
        }

        // Try direct numeric output
        if let prob = output.featureValue(for: "threatProbability")?.doubleValue {
            Self.logger.debug("Scored via direct double output: \(prob)")
            return ScoringResult(threatProbability: max(0, min(1, prob)))
        }

        // Try predicted label as fallback — convert class to rough probability
        if let labelFeature = output.featureValue(for: "threatLabel") {
            let label: Int
            if labelFeature.type == .int64 {
                label = Int(labelFeature.int64Value)
            } else if labelFeature.type == .string {
                label = ["benign": 0, "suspicious": 1, "malicious": 2][labelFeature.stringValue] ?? 0
            } else {
                label = 0
            }
            let score = [0: 0.1, 1: 0.55, 2: 0.9][label] ?? 0.1
            Self.logger.debug("Scored via label fallback: label=\(label) → \(score)")
            return ScoringResult(threatProbability: score)
        }

        Self.logger.error("BehavioralScorer: Unexpected model output format. Returning 0.")
        return ScoringResult(threatProbability: 0)
    }
}

// MARK: - ScoringResult

/// Internal result from CoreML inference.
private struct ScoringResult {
    /// Threat probability in [0, 1].
    let threatProbability: Double
}
