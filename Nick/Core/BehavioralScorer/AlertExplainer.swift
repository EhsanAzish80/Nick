// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import FoundationModels
import os

// MARK: - AlertExplainer

/// Generates natural-language explanations for threat alerts using the on-device
/// Foundation Models LLM.
///
/// All inference runs on-device — no data leaves the user's machine. This is a
/// deliberate architectural requirement for a security tool.
///
/// If the model session throws (e.g. model unavailable, context limit exceeded),
/// `explain(alert:topFeatures:)` falls back to a deterministic template-based
/// explanation so the caller always receives a non-empty, actionable string.
final class AlertExplainer: @unchecked Sendable {

    // MARK: - Private

    private let promptBuilder = ExplanationPromptBuilder()
    private let session = LanguageModelSession()
    private static let logger = Logger(subsystem: "com.ehsanazish.nick", category: "AlertExplainer")

    // MARK: - Init

    /// Creates a new instance. No configuration required.
    init() {}

    // MARK: - Public API

    /// Generates a natural-language explanation for a threat alert.
    ///
    /// Uses Foundation Models on-device LLM for a context-aware 2–3 sentence
    /// explanation in plain English. Falls back to a deterministic template if
    /// the model session throws for any reason.
    ///
    /// - Parameters:
    ///   - alert: The correlated threat alert to explain.
    ///   - topFeatures: Up to 5 ranked contributing features from `BehavioralScorer`.
    ///     Pass `[]` if no ML scores are available; the fallback templates handle this.
    /// - Returns: A 2–3 sentence plain-English explanation string. Never empty.
    func explain(alert: ThreatAlert, topFeatures: [(name: String, contribution: Double)]) async -> String {
        // SECURITY: Foundation Models processes data entirely on-device.
        // No prompt content, alert metadata, or user data is transmitted externally.
        let prompt = promptBuilder.buildPrompt(for: alert, topFeatures: topFeatures)
        do {
            let response = try await session.respond(to: prompt)
            let text = response.content.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !text.isEmpty else {
                return promptBuilder.buildTemplatedExplanation(for: alert, topFeatures: topFeatures)
            }
            Self.logger.info("Foundation Models explanation generated for alert: \(alert.id)")
            return text
        } catch {
            Self.logger.error("Foundation Models failed, using template fallback: \(error.localizedDescription)")
            return promptBuilder.buildTemplatedExplanation(for: alert, topFeatures: topFeatures)
        }
    }
}
