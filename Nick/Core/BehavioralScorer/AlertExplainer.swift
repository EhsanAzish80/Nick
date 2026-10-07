// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - AlertExplainer

/// Generates deterministic, local explanations for threat alerts.
///
/// Foundation Models integration remains available for a later gated rollout,
/// but live monitoring must not depend on a model runtime to remain stable.
/// The result is display text only; this API has no access to verdict, severity,
/// suppression, scoring, or privileged response operations.
actor AlertExplainer {

    // MARK: - Private

    private let promptBuilder = ExplanationPromptBuilder()

    // MARK: - Init

    init() {
        // Creates a new instance. No configuration required.
    }

    // MARK: - Public API

    /// Generates a natural-language explanation for a threat alert.
    ///
    /// Returns a deterministic explanation in plain English. Model-generated
    /// explanations stay disabled until their runtime is proven safe under the
    /// concurrent load of live monitoring.
    ///
    /// - Parameters:
    ///   - alert: The correlated threat alert to explain.
    ///   - topFeatures: Up to 5 ranked contributing features from `BehavioralScorer`.
    ///     Pass `[]` if no ML scores are available; the fallback templates handle this.
    /// - Returns: A 2–3 sentence plain-English explanation string. Never empty.
    func explain(alert: ThreatAlert, topFeatures: [(name: String, contribution: Double)]) async -> String {
        promptBuilder.buildTemplatedExplanation(for: alert, topFeatures: topFeatures)
    }
}
