// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import NetworkExtension
import os
import Security

// MARK: - FilterDataProvider

/// `NEFilterDataProvider` subclass that evaluates outbound network flows
/// against multiple detection layers:
///
/// 1. **Blocklist** (`NetworkBlocklist`) — known malware C2 domains and IPs.
/// 2. **Suspicious port check** — allow-list of well-known safe ports; flag unknown.
/// 3. **ScamGuardian** — phishing / typosquat heuristics.
/// 4. **ConnectionTracker** — per-app connection-rate anomaly detection.
///
/// Flows that pass all checks are allowed; flows that fail any check are
/// dropped and logged.
final class FilterDataProvider: NEFilterDataProvider {

    // MARK: - Private Properties

    private let blocklist      = NetworkBlocklist.shared
    private let tracker        = ConnectionTracker()
    private let scamGuardian   = ScamGuardian()
    private let eventStore     = NetworkBlockEventStore()
    private var healthTimer: DispatchSourceTimer?
    /// Resolving a source audit token through Security.framework is relatively
    /// expensive and can emit trust errors for unsigned/system-generated flows.
    /// Audit tokens are stable for a process lifetime, so cache positive and
    /// negative lookups instead of repeating them for every socket.
    private let signingIdentifierCache: NSCache<NSData, NSString> = {
        let cache = NSCache<NSData, NSString>()
        cache.countLimit = 512
        return cache
    }()
    private let unknownSigningIdentifier = NSString(string: "\u{0}")

    private static let logger = Logger(
        subsystem: "com.ehsanazish.nick.NickNetFilter",
        category:  "FilterDataProvider"
    )

    /// Well-known ports that are considered "normal" outbound traffic.
    private let allowlistedPorts: Set<Int> = [
        80, 443, 53, 22, 587, 465, 993, 995, 143, 110, 25, 8080, 8443
    ]

    // MARK: - NEFilterDataProvider

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        Self.logger.info("NickNetFilter: content filter starting")
        publishHealth()
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + 10, repeating: 10)
        timer.setEventHandler { [weak self] in self?.publishHealth() }
        timer.resume()
        healthTimer = timer
        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        Self.logger.info("NickNetFilter: content filter stopping (reason: \(reason.rawValue))")
        healthTimer?.cancel()
        healthTimer = nil
        completionHandler()
    }

    private func publishHealth() {
        guard let url = NetworkProtectionSharedStore.healthURL() else {
            Self.logger.error("Could not resolve Network Filter health location")
            return
        }
        let health: [String: Any] = [
            "active": true,
            "updatedAt": Date().timeIntervalSince1970,
            // Keep health and provider configuration on the same behavior
            // version so an old running filter never receives a false green.
            "configurationVersion": NetworkProtectionConfiguration.configurationVersion,
            "failOpen": true
        ]
        do {
            try FileManager.default.createDirectory(
                at: url.deletingLastPathComponent(),
                withIntermediateDirectories: true,
                attributes: nil
            )
            let data = try JSONSerialization.data(withJSONObject: health)
            try data.write(to: url, options: .atomic)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o644],
                ofItemAtPath: url.path
            )
        } catch {
            Self.logger.error("Could not publish filter health: \(error.localizedDescription)")
        }
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            return .allow()
        }

        // Extract remote host + port.
        // remoteFlowEndpoint returns NWEndpoint (Swift enum) on macOS 15+.
        // Fall back to remoteHostname when the endpoint isn't resolved yet.
        let host: String
        let port: Int

        // Prefer the original hostname. A resolved endpoint is commonly only
        // an IP address, which would make domain blocklists and Scam Guardian
        // ineffective even though NetworkExtension retained the DNS name.
        if let hostname = socketFlow.remoteHostname, !hostname.isEmpty {
            host = hostname
            if let endpoint = socketFlow.remoteFlowEndpoint,
               case .hostPort(_, let p) = endpoint {
                port = Int(p.rawValue)
            } else {
                port = -1
            }
        } else if let endpoint = socketFlow.remoteFlowEndpoint,
                  case .hostPort(let h, let p) = endpoint {
            host = "\(h)"
            port = Int(p.rawValue)
        } else {
            return .allow()  // no destination info yet; allow and re-evaluate later
        }

        let portString = port >= 0 ? "\(port)" : "?"
        let appID = signingIdentifier(for: flow.sourceAppAuditToken) ?? "unknown"
        let configuration = NetworkProtectionConfiguration(
            vendorConfiguration: filterConfiguration.vendorConfiguration
        )
        let verdict = NetworkProtectionPolicy(configuration: configuration).evaluate(
            host: host,
            appIdentifier: appID,
            isBlocklisted: blocklist.isBlocked(host:),
            isScam: scamGuardian.isSuspicious(host:)
        )

        if case .block(let reason) = verdict {
            Self.logger.warning(
                "NickNetFilter: BLOCKED (\(reason.rawValue)) \(appID) → \(host):\(portString)"
            )
            eventStore.append(NetworkBlockEvent(
                host: NetworkProtectionConfiguration.normalizedDomain(host) ?? host,
                appIdentifier: appID == "unknown" ? nil : appID,
                reason: reason
            ))
            let result = NEFilterNewFlowVerdict.drop()
            result.shouldReport = true
            return result
        }

        // ── Layer 2: Suspicious port ──────────────────────────────────────
        if port > 1024 && !allowlistedPorts.contains(port) {
            Self.logger.info("NickNetFilter: suspicious port \(port) from \(appID) → \(host)")
            // Warn but do not block — not all high-port traffic is malicious.
            // ConnectionTracker will escalate if rates are abnormal.
        }

        // ── Layer 3: Connection-rate tracking ─────────────────────────────
        if tracker.shouldBlock(appID: appID, remoteHost: host) {
            // Browsers routinely create hundreds of connections across many
            // hosts. A rate anomaly is useful telemetry, but is not sufficient
            // evidence to cut off an app's networking.
            Self.logger.warning("NickNetFilter: rate anomaly (allowed) \(appID) → \(host):\(portString)")
        }

        return .allow()
    }

    private func signingIdentifier(for auditToken: Data?) -> String? {
        guard let auditToken else { return nil }
        let cacheKey = auditToken as NSData
        if let cached = signingIdentifierCache.object(forKey: cacheKey) {
            return cached == unknownSigningIdentifier ? nil : cached as String
        }

        let resolved: String? = Self.resolveSigningIdentifier(for: auditToken)
        signingIdentifierCache.setObject(
            resolved.map(NSString.init(string:)) ?? unknownSigningIdentifier,
            forKey: cacheKey
        )
        return resolved
    }

    private static func resolveSigningIdentifier(for auditToken: Data) -> String? {
        var code: SecCode?
        let attributes = [kSecGuestAttributeAudit: auditToken] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code
        else { return nil }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode
        else { return nil }

        var information: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
                == errSecSuccess,
              let dictionary = information as? [CFString: Any]
        else { return nil }
        return dictionary[kSecCodeInfoIdentifier] as? String
    }

}

private final class NetworkBlockEventStore {
    private let lock = NSLock()

    func append(_ event: NetworkBlockEvent) {
        guard let url = NetworkProtectionSharedStore.eventsURL() else { return }
        lock.withLock {
            do {
                try FileManager.default.createDirectory(
                    at: url.deletingLastPathComponent(),
                    withIntermediateDirectories: true,
                    attributes: [.posixPermissions: 0o755]
                )
                var events = (try? Data(contentsOf: url))
                    .flatMap { try? JSONDecoder().decode([NetworkBlockEvent].self, from: $0) }
                    ?? []
                events.removeAll {
                    $0.host == event.host
                        && $0.appIdentifier == event.appIdentifier
                        && event.timestamp.timeIntervalSince($0.timestamp) < 10
                }
                events.insert(event, at: 0)
                if events.count > NetworkProtectionSharedStore.maximumEventCount {
                    events.removeLast(events.count - NetworkProtectionSharedStore.maximumEventCount)
                }
                let data = try JSONEncoder().encode(events)
                try data.write(to: url, options: .atomic)
                try FileManager.default.setAttributes(
                    [.posixPermissions: 0o644],
                    ofItemAtPath: url.path
                )
            } catch {
                // Filtering must remain deterministic even if observability is
                // unavailable. Never change a verdict because logging failed.
            }
        }
    }
}
