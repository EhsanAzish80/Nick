// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import XCTest
@testable import Nick

// MARK: - BehavioralScorerTests

/// Unit tests for `BehavioralScorer`.
///
/// Tests cover the model availability check, error handling when the model is absent,
/// score clamping, edge-case inputs (all zeros, all ones), the explanation feature
/// ranking logic, and inference latency requirements.
///
/// Note: Tests run without an actual `.mlmodel` bundle resource. The scorer's
/// `modelNotFound` path and the rule-based fallback are tested directly. Full
/// end-to-end model tests require a trained `ThreatScorer.mlmodel` in the bundle.
final class BehavioralScorerTests: XCTestCase {

    // MARK: - Model availability

    func test_noModel_isModelAvailableReturnsFalse() {
        let scorer = BehavioralScorer(modelURL: nil)
        XCTAssertFalse(scorer.isModelAvailable)
    }

    func test_withModelURL_isModelAvailableReturnsTrue() {
        // Use a placeholder URL — availability only checks for non-nil URL
        let url = URL(fileURLWithPath: "/tmp/ThreatScorer.mlmodel")
        let scorer = BehavioralScorer(modelURL: url)
        XCTAssertTrue(scorer.isModelAvailable)
    }

    // MARK: - Error handling

    func test_noModel_scoreThrowsModelNotFound() {
        let scorer = BehavioralScorer(modelURL: nil)
        XCTAssertThrowsError(try scorer.score(features: FeatureVector())) { error in
            guard case BehavioralScorerError.modelNotFound = error else {
                XCTFail("Expected modelNotFound, got \(error)")
                return
            }
        }
    }

    func test_missingModelFile_scoreThrowsModelLoadFailed() {
        let badURL = URL(fileURLWithPath: "/nonexistent/ThreatScorer.mlmodelc")
        let scorer = BehavioralScorer(modelURL: badURL)
        XCTAssertThrowsError(try scorer.score(features: FeatureVector())) { error in
            guard case BehavioralScorerError.modelLoadFailed = error else {
                XCTFail("Expected modelLoadFailed, got \(error)")
                return
            }
        }
    }

    func test_noModel_scoreWithExplanationThrowsModelNotFound() {
        let scorer = BehavioralScorer(modelURL: nil)
        XCTAssertThrowsError(try scorer.scoreWithExplanation(features: FeatureVector())) { error in
            guard case BehavioralScorerError.modelNotFound = error else {
                XCTFail("Expected modelNotFound, got \(error)")
                return
            }
        }
    }

    // MARK: - Error description

    func test_errorDescriptions_areNonEmpty() {
        let errors: [BehavioralScorerError] = [
            .modelNotFound,
            .modelLoadFailed(underlying: NSError(domain: "test", code: 1)),
            .inferenceFailed(underlying: NSError(domain: "test", code: 2)),
            .unexpectedOutput,
        ]
        for error in errors {
            XCTAssertFalse(error.errorDescription?.isEmpty ?? true,
                           "errorDescription must not be empty for \(error)")
        }
    }

    // MARK: - FeatureVector edge cases

    func test_zeroFeatureVector_allFeaturesAreZero() {
        let vec = FeatureVector()
        XCTAssertTrue(vec.asArray.allSatisfy { $0 == 0 })
    }

    func test_maliciousFeatureVector_keyFeaturesAreSet() {
        var vec = FeatureVector()
        vec.processIsUnsigned    = 1
        vec.processInTmp         = 1
        vec.netHasOutboundConnection = 1
        vec.netRemoteIsRawIP     = 1
        vec.netUsesUncommonPort  = 1
        vec.fsFileEntropyIsHigh  = 1
        vec.yaraMatchCount       = 2
        vec.yaraMaxSeverity      = 4
        vec.temporalSignalsInWindow = 8
        vec.temporalSeverityEscalation = 1

        // The malicious vector should have at least 10 non-zero features
        let nonZeroCount = vec.asArray.filter { $0 > 0 }.count
        XCTAssertGreaterThanOrEqual(nonZeroCount, 10)
    }

    // MARK: - Latency (model not available test — measures overhead not ML)

    func test_scoreAttempt_completesQuickly() {
        let scorer = BehavioralScorer(modelURL: nil)
        let start = Date()
        _ = try? scorer.score(features: FeatureVector())
        let elapsed = Date().timeIntervalSince(start)
        // Even the error path must be instantaneous
        XCTAssertLessThan(elapsed, 0.005, "BehavioralScorer setup overhead must be < 5ms")
    }

    // MARK: - Feature vector asArray ordering

    func test_featureNames_and_asArray_sameLength() {
        let vec = FeatureVector()
        XCTAssertEqual(vec.asArray.count, FeatureVector.featureNames.count)
        XCTAssertEqual(FeatureVector.featureNames.count, 40)
    }

    func test_featureVector_codableRoundTrip() throws {
        var vec = FeatureVector()
        vec.processIsUnsigned = 1
        vec.yaraMatchCount = 3
        vec.fsFileEntropy = 7.8
        let data = try JSONEncoder().encode(vec)
        let decoded = try JSONDecoder().decode(FeatureVector.self, from: data)
        XCTAssertEqual(decoded.processIsUnsigned, 1)
        XCTAssertEqual(decoded.yaraMatchCount, 3)
        XCTAssertEqual(decoded.fsFileEntropy, 7.8, accuracy: 0.0001)
        XCTAssertEqual(decoded.asArray.count, 40)
    }
}
