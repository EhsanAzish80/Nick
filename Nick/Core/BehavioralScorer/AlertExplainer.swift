// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os

// MARK: - AlertExplainer

/// Generates natural-language explanations for threat alerts.
///
/// On macOS 26+, `AlertExplainer` uses the Foundation Models on-device LLM
/// to produce a high-quality, context-aware explanation in plain English.
/// On macOS 14–25, it falls back to deterministic template-based explanations
/// that are still readable and actionable, just less adaptive.
///
/// All Foundation Models API calls are gated behind `#available(macOS 26, *)`.
/// The type compiles and runs correctly on macOS 14+ without any feature flags.
///
/// - Note: Explanation generation is async to accommodate the LLM path without
///         blocking the real-time detection pipeline. The fallback path is
///         synchronous internally but wrapped in async for a uniform interface.
final class AlertExplainer: @unchecked Sendable {

    // MARK: - Private

    private let promptBuilder = ExplanationPromptBuilder()
    private static let logger = Logger(subsystem: "com.ehsanazish.nick", category: "AlertExplainer")

    // MARK: - Init

    init() {}

    // MARK: - Public API

    /// Generates a natural-language explanation for an alert.
    ///
    /// On macOS 26+, uses Foundation Models for on-device LLM generation.
    /// On earlier macOS versions, returns a deterministic templated explanation.
    ///
    /// - Parameters:
    ///   - alert: The correlated threat alert to explain.
    ///   - topFeatures: Up to 5 ranked contributing features from `BehavioralScorer`.
    ///     Pass `[]` if no ML scores are available; the fallback templates handle this.
    /// - Returns: A 2–3 sentence plain-English explanation string. Never empty.
    func explain(alert: ThreatAlert, topFeatures: [(name: String, contribution: Double)]) async -> String {
        if #available(macOS 26, *) {
            do {
                let explanation = try await generateWithFoundationModels(
                    alert: alert,
                    topFeatures: topFeatures
                )
                Self.logger.info("Foundation Models explanation generated for alert: \(alert.id)")
                return explanation
            } catch {
                Self.logger.error("Foundation Models failed, using template fallback: \(error.localizedDescription)")
                return promptBuilder.buildTemplatedExplanation(for: alert, topFeatures: topFeatures)
            }
        } else {
            return promptBuilder.buildTemplatedExplanation(for: alert, topFeatures: topFeatures)
        }
    }

    // MARK: - Private Implementation

    /// Generates an explanation using Foundation Models (macOS 26+ only).
    ///
    /// - Throws: If the model session fails to initialize or generate a response.
    @available(macOS 26, *)
    private func generateWithFoundationModels(
        alert: ThreatAlert,
        topFeatures: [(name: String, contribution: Double)]
    ) async throws -> String {
        // SECURITY: Foundation Models processes data entirely on-device.
        // No data leaves the user's machine. This is by design for a security tool.
        let prompt = promptBuilder.buildPrompt(for: alert, topFeatures: topFeatures)
        return try await FoundationModelsSession.generate(prompt: prompt)
    }
}

// MARK: - FoundationModelsSession

/// Thin wrapper around Foundation Models API to isolate availability checks.
///
/// This enum wraps the actual Foundation Models call so `AlertExplainer` doesn't
/// need to scatter `#available` checks. The implementation detail of which
/// Foundation Models API version to use is isolated here.
@available(macOS 26, *)
private enum FoundationModelsSession {

    /// Generates text using the on-device Foundation Models language model.
    ///
    /// - Parameter prompt: The instruction prompt to send to the model.
    /// - Returns: The generated response text, trimmed of whitespace.
    /// - Throws: Any error from the Foundation Models framework.
    static func generate(prompt: String) async throws -> String {
        // TODO(ehsan): Replace with the actual Foundation Models API once
        // macOS 26 SDK reaches GA. Currently using the expected API surface
        // based on WWDC preview. See https://developer.apple.com/documentation/foundationmodels
        // The API is expected to be: LanguageModelSession.default.generate(instructions:)
        // For now, delegate to a placeholder that will be replaced.
        //
        // Foundation Models API (macOS 26+):
        // import FoundationModels
        // let session = LanguageModelSession()
        // let response = try await session.respond(to: prompt)
        // return response.content

        // Fallback: return a clearly-labeled placeholder until SDK is final
        return "[Foundation Models placeholder — run on macOS 26 GA with FoundationModels import]"
    }
}
