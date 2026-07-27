// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation
import os
import SystemExtensions

// MARK: - ExtensionState

/// The current lifecycle state of the `NickExtension` System Extension.
public enum ExtensionState: String, Sendable {
    case unknown
    case installing
    case needsUserApproval   // User must approve in System Settings → Privacy & Security
    case installed
    case uninstalling
    case failed
}

// MARK: - ExtensionManager

/// Manages the installation and removal lifecycle of the `NickExtension`
/// Endpoint Security System Extension using `OSSystemExtensionManager`.
///
/// Publish `extensionState` to the UI so the onboarding flow can prompt the
/// user to approve the extension in System Settings when needed.
///
/// **Usage:**
/// ```swift
/// let mgr = ExtensionManager()
/// mgr.installExtension()
/// ```
@MainActor
@Observable
public final class ExtensionManager: NSObject {

    // MARK: - Observable State

    /// Current installation state of the System Extension.
    public private(set) var extensionState: ExtensionState = .unknown

    /// Non-nil when the last operation ended in failure.
    public private(set) var lastError: Error?

    /// Converts opaque System Extensions errors into an action the user can
    /// understand. A code-signature failure cannot be repaired by repeatedly
    /// pressing Install; the app must be rebuilt with a valid certificate (or
    /// notarized when distributed with Developer ID).
    public static func userFacingInstallationError(_ error: Error) -> String {
        let nsError = error as NSError
        if nsError.domain == OSSystemExtensionErrorDomain,
           nsError.code == OSSystemExtensionError.Code.codeSignatureInvalid.rawValue {
            return """
            Nick's signing certificate is not trusted. For local testing, renew the Apple Development certificate in Xcode → Settings → Accounts, then rebuild Nick and move that new build to Applications. Release builds must be notarized before installation.
            """
        }

        return error.localizedDescription
    }

    // MARK: - Private

    private nonisolated static let logger = Logger(
        subsystem: "com.ehsanazish.nick",
        category: "ExtensionManager"
    )
    private static let activationCompletedKey = "endpointSecurityExtensionActivationCompleted"
    private static let activatedVersionKey = "endpointSecurityExtensionActivatedVersion"

    public override init() {
        super.init()
        let activatedVersion = UserDefaults.standard.string(forKey: Self.activatedVersionKey)
        if UserDefaults.standard.bool(forKey: Self.activationCompletedKey),
           activatedVersion == Self.bundledExtensionVersion {
            extensionState = .installed
        }
    }

    private static var bundledExtensionVersion: String? {
        guard let extensionURL = Bundle.main.builtInPlugInsURL?
            .deletingLastPathComponent()
            .appendingPathComponent("SystemExtensions")
            .appendingPathComponent("com.ehsanazish.nick.NickExtension.systemextension"),
              let bundle = Bundle(url: extensionURL) else {
            return nil
        }
        return bundle.object(forInfoDictionaryKey: kCFBundleVersionKey as String) as? String
    }

    // MARK: - Public API

    /// Requests activation of the `NickExtension` System Extension.
    ///
    /// On first run the system will prompt the user to approve the extension
    /// in **System Settings → Privacy & Security**. `extensionState` transitions
    /// to `.needsUserApproval` in that case.
    public func installExtension() {
        extensionState = .installing
        lastError = nil

        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: NickExtensionConstants.extensionBundleID,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        Self.logger.info("Submitted extension activation request")
    }

    /// Requests deactivation (removal) of the `NickExtension` System Extension.
    public func uninstallExtension() {
        extensionState = .uninstalling
        lastError = nil
        UserDefaults.standard.set(false, forKey: Self.activationCompletedKey)
        UserDefaults.standard.removeObject(forKey: Self.activatedVersionKey)

        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: NickExtensionConstants.extensionBundleID,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        Self.logger.info("Submitted extension deactivation request")
    }
}

// MARK: - OSSystemExtensionRequestDelegate

extension ExtensionManager: OSSystemExtensionRequestDelegate {

    public nonisolated func request(
        _: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        // Always replace with the bundled version so updates apply on next launch.
        Self.logger.info("Replacing extension \(existing.bundleShortVersion) → \(ext.bundleShortVersion)")
        return .replace
    }

    public nonisolated func requestNeedsUserApproval(_: OSSystemExtensionRequest) {
        Task { @MainActor in
            Self.logger.notice("Extension requires user approval in System Settings")
            extensionState = .needsUserApproval
        }
    }

    public nonisolated func request(
        _: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        Task { @MainActor in
            switch result {
            case .completed:
                Self.logger.info("Extension request completed successfully")
                UserDefaults.standard.set(true, forKey: Self.activationCompletedKey)
                UserDefaults.standard.set(
                    Self.bundledExtensionVersion,
                    forKey: Self.activatedVersionKey
                )
                extensionState = .installed
            case .willCompleteAfterReboot:
                Self.logger.notice("Extension will activate after reboot")
                extensionState = .needsUserApproval
            @unknown default:
                Self.logger.warning("Unknown extension request result: \(result.rawValue)")
                extensionState = .installed
            }
        }
    }

    public nonisolated func request(
        _: OSSystemExtensionRequest,
        didFailWithError error: Error
    ) {
        Task { @MainActor in
            Self.logger.error("Extension request failed: \(error.localizedDescription)")
            extensionState = .failed
            lastError = error
        }
    }
}
