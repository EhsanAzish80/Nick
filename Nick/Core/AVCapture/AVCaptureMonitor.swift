// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AVFoundation
import AppKit
import CoreAudio
import CoreMediaIO
import Darwin
import Foundation
import Observation
import os

// MARK: - AVCaptureMonitor

/// Detects active camera and microphone usage by any process.
///
/// On each `start()` call the monitor snapshots all CoreMediaIO video devices and
/// all CoreAudio input devices, then property listeners track both active and
/// inactive transitions. A `ThreatSignal` is emitted once per state change,
/// preventing duplicates across repeated callbacks.
///
/// Public device-client evidence is used when macOS supplies it. If camera APIs
/// expose activity without a client PID, Nick may retain the signed foreground
/// app as explicitly non-authoritative context; it must never be described or
/// trusted as the owner of the capture session.
///
/// - Note: `AVCaptureDevice` connection/disconnection notifications are registered
///         for real-time supplemental coverage (physical device plug events).
@Observable
@MainActor
final class AVCaptureMonitor: MonitorProtocol {

    // MARK: - MonitorProtocol

    let monitorType: MonitorType = .avCapture
    private(set) var isRunning = false

    // MARK: - Published State

    /// `true` while any CMIO video device reports streaming activity.
    private(set) var isCameraActive: Bool = false

    /// `true` while any CoreAudio input device reports streaming activity.
    private(set) var isMicrophoneActive: Bool = false

    // MARK: - Private

    private var pendingSignals: [ThreatSignal] = []
    var signalHandler: ((ThreatSignal) async -> Void)?

    /// Tracks device IDs → last-known running state to detect new activations.
    private var knownVideoState:  [CMIODeviceID:  Bool] = [:]
    private var knownAudioState:  [AudioDeviceID: Bool] = [:]
    private var videoAttribution: [CMIODeviceID: DetectedCaptureProcess] = [:]
    private var audioAttribution: [AudioDeviceID: DetectedCaptureProcess] = [:]

    private var deviceObservers: [NSObjectProtocol] = []
    private var videoActivityListeners: [CMIODeviceID: CMIOObjectPropertyListenerBlock] = [:]
    private var audioActivityListeners: [AudioDeviceID: AudioObjectPropertyListenerBlock] = [:]
    private let activityListenerQueue = DispatchQueue(
        label: "com.ehsanazish.nick.capture-activity",
        qos: .userInitiated
    )

    private static let log = Logger(
        subsystem: "com.ehsanazish.nick",
        category:  "AVCaptureMonitor"
    )

    // MARK: - MonitorProtocol

    func start() async throws {
        guard !isRunning else { return }
        isRunning = true
        defer { isRunning = false }

        await scanAllDevices()
        registerDeviceNotifications()
        registerActivityListeners()

        // Only log when a camera or mic is actually active — avoids CMIO framework noise
        // on machines without supported camera hardware.
        if isCameraActive || isMicrophoneActive {
            Self.log.info("AVCapture scan — camera:\(self.isCameraActive) mic:\(self.isMicrophoneActive) signals:\(self.pendingSignals.count)")
        }
    }

    func stop() async {
        unregisterDeviceNotifications()
        unregisterActivityListeners()
        isRunning = false
    }

    func latestSignals() async -> [ThreatSignal] {
        defer { pendingSignals.removeAll() }
        return pendingSignals
    }

    // MARK: - Device Scanning

    /// Scans all camera and microphone devices for state changes.
    func scanAllDevices() async {
        await scanCameraDevices()
        await scanMicrophoneDevices()
    }

    private func scanCameraDevices() async {
        let deviceIDs = CaptureDeviceAccessor.videoDeviceIDs()
        var anyRunning = false

        for deviceID in deviceIDs {
            let running    = CaptureDeviceAccessor.isCMIODeviceRunning(deviceID)
            if running { anyRunning = true }
            processCameraState(
                deviceID: deviceID,
                running: running,
                deviceName: CaptureDeviceAccessor.cmioDeviceName(deviceID) ?? "Camera",
                detectedProcess: running
                    ? CaptureProcessScanner.cameraOwner(deviceID: deviceID)
                        ?? CaptureProcessScanner.frontmostContext()
                    : nil
            )
        }

        isCameraActive = anyRunning
    }

    private func scanMicrophoneDevices() async {
        let deviceIDs = CaptureDeviceAccessor.audioInputDeviceIDs()
        var anyRunning = false

        for deviceID in deviceIDs {
            let running    = CaptureDeviceAccessor.isAudioDeviceRunning(deviceID)
            if running { anyRunning = true }
            processMicrophoneState(
                deviceID: deviceID,
                running: running,
                deviceName: CaptureDeviceAccessor.audioDeviceName(deviceID) ?? "Microphone",
                detectedProcess: running
                    ? CaptureProcessScanner.microphoneOwner(deviceID: deviceID)
                        ?? CaptureProcessScanner.frontmostContext()
                    : nil
            )
        }

        isMicrophoneActive = anyRunning
    }

    /// State reducers are internal so tests exercise the same transition path
    /// used by the CMIO/CoreAudio listeners without requiring physical hardware.
    func processCameraState(
        deviceID: CMIODeviceID,
        running: Bool,
        deviceName: String,
        detectedProcess: DetectedCaptureProcess?
    ) {
        let wasRunning = knownVideoState[deviceID] ?? false
        if running && !wasRunning {
            if let detectedProcess { videoAttribution[deviceID] = detectedProcess }
            emit(makeCaptureSignal(
                mediaType: "camera", deviceName: deviceName, process: detectedProcess
            ))
            Self.log.notice("Camera activated: \(deviceName) — attribution \(detectedProcess?.confidence ?? "unavailable")")
        } else if !running && wasRunning {
            let process = videoAttribution.removeValue(forKey: deviceID)
            emit(makeCaptureSignal(
                mediaType: "camera", deviceName: deviceName, process: process, active: false
            ))
            Self.log.notice("Camera became inactive: \(deviceName)")
        }
        knownVideoState[deviceID] = running
    }

    func processMicrophoneState(
        deviceID: AudioDeviceID,
        running: Bool,
        deviceName: String,
        detectedProcess: DetectedCaptureProcess?
    ) {
        let wasRunning = knownAudioState[deviceID] ?? false
        if running && !wasRunning {
            if let detectedProcess { audioAttribution[deviceID] = detectedProcess }
            emit(makeCaptureSignal(
                mediaType: "microphone", deviceName: deviceName, process: detectedProcess
            ))
            Self.log.notice("Microphone activated: \(deviceName) — attribution \(detectedProcess?.confidence ?? "unavailable")")
        } else if !running && wasRunning {
            let process = audioAttribution.removeValue(forKey: deviceID)
            emit(makeCaptureSignal(
                mediaType: "microphone", deviceName: deviceName, process: process, active: false
            ))
            Self.log.notice("Microphone became inactive: \(deviceName)")
        }
        knownAudioState[deviceID] = running
    }

    // MARK: - Signal Generation

    private func emit(_ signal: ThreatSignal) {
        pendingSignals.append(signal)
        guard let signalHandler else { return }
        Task { await signalHandler(signal) }
    }

    /// Builds a `ThreatSignal` for a capture-device activation event.
    ///
    /// Made `internal` for direct unit-test access.
    func makeCaptureSignal(
        mediaType:  String,
        deviceName: String,
        process:    DetectedCaptureProcess?,
        active:     Bool = true
    ) -> ThreatSignal {
        let processName = process?.name ?? "unavailable"

        let severity: SignalSeverity = {
            guard active else { return .info }
            guard let p = process else { return .info }
            guard p.confidence == "authoritative" else { return .info }
            if Self.isSimulatorRuntimeProcess(p.path) { return .info }
            switch p.signingStatus {
            case .unsigned, .invalid: return .high
            default:                  return .medium
            }
        }()

        let processInfo: NickProcessInfo? = process.map { p in
            NickProcessInfo(
                pid:         p.pid,
                path:        p.path,
                name:        p.name,
                parentPID:   0,
                parentName:  nil,
                signingStatus: p.signingStatus,
                metadata: ProcessMetadata()
            )
        }

        let deliveryLevel = active ? captureDeliveryLevel(for: process) : "silent"
        return ThreatSignal(
            source:      .avCapture,
            severity:    severity,
            title: active
                ? "\(deviceName) activated by \(processName)"
                : "\(deviceName) stopped being active",
            description: captureDescription(
                active: active, deviceName: deviceName, process: process
            ),
            context: ThreatSignalContext(
                processInfo: processInfo,
                metadata: [
                    "mediaType":  mediaType,
                    "deviceName": deviceName,
                    "process":    processName,
                    "reason": active ? "capture_device_active" : "capture_device_inactive",
                    "captureState": active ? "active" : "inactive",
                    "attributionConfidence": process?.confidence ?? "unavailable",
                    "deliveryLevel": deliveryLevel
                ]
            )
        )
    }

    private func captureDeliveryLevel(for process: DetectedCaptureProcess?) -> String {
        guard let process,
              process.confidence == "authoritative",
              case .signed(let teamID, let signingID?) = process.signingStatus else {
            return "interrupt"
        }
        let identityKey = "\(teamID)|\(signingID)"
            .data(using: .utf8)?.base64EncodedString() ?? "invalid"
        let firstUseKey = "nickCaptureSeenValidatedIdentity.\(identityKey)"
        let firstUse = !UserDefaults.standard.bool(forKey: firstUseKey)
        UserDefaults.standard.set(true, forKey: firstUseKey)
        let application = NSRunningApplication(processIdentifier: process.pid)
        let isBackground = application?.activationPolicy == .prohibited
            || !Self.hasVisibleWindow(pid: process.pid)
        let session = CGSessionCopyCurrentDictionary() as? [String: Any]
        let screenLocked = (session?["CGSSessionScreenIsLocked"] as? Bool) == true
        let idle = CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: .null) >= 300
        return firstUse || isBackground || screenLocked || idle ? "interrupt" : "silent"
    }

    private static func hasVisibleWindow(pid: pid_t) -> Bool {
        guard let windows = CGWindowListCopyWindowInfo(
            [.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID
        ) as? [[String: Any]] else { return false }
        return windows.contains { window in
            (window[kCGWindowOwnerPID as String] as? pid_t) == pid
                && (window[kCGWindowAlpha as String] as? Double ?? 0) > 0
                && (window[kCGWindowLayer as String] as? Int ?? 1) == 0
        }
    }

    private func captureDescription(
        active: Bool,
        deviceName: String,
        process: DetectedCaptureProcess?
    ) -> String {
        guard active else {
            return "The \(deviceName) stopped streaming."
        }
        guard let process else {
            return "The \(deviceName) began streaming. macOS did not provide Nick with reliable app ownership for this event."
        }
        if process.confidence == "authoritative" {
            return "The \(deviceName) began streaming and macOS attributed the session to \(process.name)."
        }
        return "The \(deviceName) began streaming while \(process.name) was the foreground app. This is context, not proof that the app owned the session."
    }

    /// Simulator runtime binaries are ad-hoc signed by design. Treating that
    /// signature as suspicious produces high-severity false positives for
    /// services such as ShazamKit's `shazamd`.
    private static func isSimulatorRuntimeProcess(_ path: String) -> Bool {
        path.contains("/CoreSimulator/") || path.contains(".simruntime/")
    }

    // MARK: - AVCaptureDevice Notifications

    private func registerDeviceNotifications() {
        let center = NotificationCenter.default

        let onConnect = center.addObserver(
            forName: AVCaptureDevice.wasConnectedNotification,
            object:  nil,
            queue:   .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.handleDeviceConnected() }
        }

        let onDisconnect = center.addObserver(
            forName: AVCaptureDevice.wasDisconnectedNotification,
            object:  nil,
            queue:   .main
        ) { [weak self] _ in
            MainActor.assumeIsolated { self?.handleDeviceDisconnected() }
        }

        deviceObservers = [onConnect, onDisconnect]
    }

    private func handleDeviceConnected() {
        Task { await scanCameraDevices() }
    }

    private func handleDeviceDisconnected() {
        isCameraActive = false
    }

    private func unregisterDeviceNotifications() {
        deviceObservers.forEach { NotificationCenter.default.removeObserver($0) }
        deviceObservers.removeAll()
    }

    /// CoreMediaIO/CoreAudio property callbacks provide activity transitions
    /// without waiting for the next full-system scan. The callback only hops to
    /// the main actor; the existing state comparison still suppresses repeats.
    private func registerActivityListeners() {
        unregisterActivityListeners()
        for deviceID in CaptureDeviceAccessor.videoDeviceIDs() {
            var address = CMIOObjectPropertyAddress(
                mSelector: CMIOObjectPropertySelector(kCMIODevicePropertyDeviceIsRunningSomewhere),
                mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
                mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain)
            )
            let listener: CMIOObjectPropertyListenerBlock = { [weak self] _, _ in
                Task { @MainActor [weak self] in await self?.scanCameraDevices() }
            }
            if CMIOObjectAddPropertyListenerBlock(
                deviceID, &address, activityListenerQueue, listener
            ) == noErr {
                videoActivityListeners[deviceID] = listener
            }
        }

        for deviceID in CaptureDeviceAccessor.audioInputDeviceIDs() {
            var address = AudioObjectPropertyAddress(
                mSelector: kAudioDevicePropertyDeviceIsRunningSomewhere,
                mScope: kAudioObjectPropertyScopeGlobal,
                mElement: kAudioObjectPropertyElementMain
            )
            let listener: AudioObjectPropertyListenerBlock = { [weak self] _, _ in
                Task { @MainActor [weak self] in await self?.scanMicrophoneDevices() }
            }
            if AudioObjectAddPropertyListenerBlock(
                deviceID, &address, activityListenerQueue, listener
            ) == noErr {
                audioActivityListeners[deviceID] = listener
            }
        }
    }

    private func unregisterActivityListeners() {
        for (deviceID, listener) in videoActivityListeners {
            var address = CMIOObjectPropertyAddress(
                mSelector: CMIOObjectPropertySelector(kCMIODevicePropertyDeviceIsRunningSomewhere),
                mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
                mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain)
            )
            CMIOObjectRemovePropertyListenerBlock(
                deviceID, &address, activityListenerQueue, listener
            )
        }
        videoActivityListeners.removeAll()
        for (deviceID, listener) in audioActivityListeners {
            var address = AudioObjectPropertyAddress(
                mSelector: kAudioDevicePropertyDeviceIsRunningSomewhere,
                mScope: kAudioObjectPropertyScopeGlobal,
                mElement: kAudioObjectPropertyElementMain
            )
            AudioObjectRemovePropertyListenerBlock(
                deviceID, &address, activityListenerQueue, listener
            )
        }
        audioActivityListeners.removeAll()
    }
}

// MARK: - DetectedCaptureProcess

/// Minimal process attribution captured at the time of device activation.
struct DetectedCaptureProcess: Sendable {
    let pid:           Int32
    let name:          String
    let path:          String
    let signingStatus: SigningStatus
    /// `authoritative` comes from a device-client PID; `contextual` means only
    /// that the signed app was foreground when the transition occurred.
    let confidence: String

    init(
        pid: Int32,
        name: String,
        path: String,
        signingStatus: SigningStatus,
        confidence: String = "authoritative"
    ) {
        self.pid = pid
        self.name = name
        self.path = path
        self.signingStatus = signingStatus
        self.confidence = confidence
    }
}

// MARK: - CaptureDeviceAccessor

/// Non-isolated wrappers around CoreMediaIO and CoreAudio C APIs.
///
/// All methods are thread-safe and may be called from any isolation context.
enum CaptureDeviceAccessor: Sendable {

    // MARK: CoreMediaIO — Camera

    /// Returns CMIODeviceIDs for all enumerated video capture devices.
    static func videoDeviceIDs() -> [CMIODeviceID] {
        var propAddress = CMIOObjectPropertyAddress(
            mSelector: CMIOObjectPropertySelector(kCMIOHardwarePropertyDevices),
            mScope:    CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
            mElement:  CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain)
        )
        var dataSize: UInt32 = 0
        guard CMIOObjectGetPropertyDataSize(
            CMIOObjectID(kCMIOObjectSystemObject), &propAddress, 0, nil, &dataSize
        ) == noErr, dataSize > 0 else { return [] }

        let count  = Int(dataSize) / MemoryLayout<CMIODeviceID>.size
        var ids    = [CMIODeviceID](repeating: 0, count: count)
        var outSize: UInt32 = 0
        guard CMIOObjectGetPropertyData(
            CMIOObjectID(kCMIOObjectSystemObject), &propAddress, 0, nil, dataSize, &outSize, &ids
        ) == noErr else { return [] }
        return ids
    }

    /// Returns `true` when the given CMIO device is actively streaming in any process.
    static func isCMIODeviceRunning(_ deviceID: CMIODeviceID) -> Bool {
        var propAddress = CMIOObjectPropertyAddress(
            mSelector: CMIOObjectPropertySelector(kCMIODevicePropertyDeviceIsRunningSomewhere),
            mScope:    CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
            mElement:  CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain)
        )
        var running: UInt32 = 0
        let size = UInt32(MemoryLayout<UInt32>.size)
        var outSize: UInt32 = 0
        return CMIOObjectGetPropertyData(
            deviceID, &propAddress, 0, nil, size, &outSize, &running
        ) == noErr && running != 0
    }

    /// Returns the localised name of a CMIO device, bridged via `AVCaptureDevice`.
    static func cmioDeviceName(_ deviceID: CMIODeviceID) -> String? {
        guard let uid = cmioDeviceUID(deviceID) else { return nil }
        return AVCaptureDevice(uniqueID: uid)?.localizedName
    }

    private static func cmioDeviceUID(_ deviceID: CMIODeviceID) -> String? {
        var propAddress = CMIOObjectPropertyAddress(
            mSelector: CMIOObjectPropertySelector(kCMIODevicePropertyDeviceUID),
            mScope:    CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
            mElement:  CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain)
        )
        var uid: Unmanaged<CFString>? = nil
        let size = UInt32(MemoryLayout<Unmanaged<CFString>?>.size)
        var outSize: UInt32 = 0
        let status = withUnsafeMutablePointer(to: &uid) { ptr in
            CMIOObjectGetPropertyData(deviceID, &propAddress, 0, nil, size, &outSize, ptr)
        }
        guard status == noErr, let raw = uid else { return nil }
        return raw.takeRetainedValue() as String
    }

    // MARK: CoreAudio — Microphone

    /// Returns `AudioDeviceID`s for all audio input devices (microphones).
    static func audioInputDeviceIDs() -> [AudioDeviceID] {
        var propAddress = AudioObjectPropertyAddress(
            mSelector: kAudioHardwarePropertyDevices,
            mScope:    kAudioObjectPropertyScopeGlobal,
            mElement:  kAudioObjectPropertyElementMain
        )
        var dataSize: UInt32 = 0
        guard AudioObjectGetPropertyDataSize(
            AudioObjectID(kAudioObjectSystemObject), &propAddress, 0, nil, &dataSize
        ) == noErr, dataSize > 0 else { return [] }

        let count  = Int(dataSize) / MemoryLayout<AudioDeviceID>.size
        var ids    = [AudioDeviceID](repeating: 0, count: count)
        var outSize = dataSize
        guard AudioObjectGetPropertyData(
            AudioObjectID(kAudioObjectSystemObject), &propAddress, 0, nil, &outSize, &ids
        ) == noErr else { return [] }
        return ids.filter { isAudioInputDevice($0) }
    }

    /// Returns `true` when the given audio device is actively recording in any process.
    static func isAudioDeviceRunning(_ deviceID: AudioDeviceID) -> Bool {
        var propAddress = AudioObjectPropertyAddress(
            mSelector: kAudioDevicePropertyDeviceIsRunningSomewhere,
            mScope:    kAudioObjectPropertyScopeGlobal,
            mElement:  kAudioObjectPropertyElementMain
        )
        var running: UInt32 = 0
        var size = UInt32(MemoryLayout<UInt32>.size)
        return AudioObjectGetPropertyData(
            deviceID, &propAddress, 0, nil, &size, &running
        ) == noErr && running != 0
    }

    /// Returns the human-readable name for an audio device.
    static func audioDeviceName(_ deviceID: AudioDeviceID) -> String? {
        var propAddress = AudioObjectPropertyAddress(
            mSelector: kAudioObjectPropertyName,
            mScope:    kAudioObjectPropertyScopeGlobal,
            mElement:  kAudioObjectPropertyElementMain
        )
        var name: Unmanaged<CFString>? = nil
        var size = UInt32(MemoryLayout<Unmanaged<CFString>?>.size)
        let status = withUnsafeMutablePointer(to: &name) { ptr in
            AudioObjectGetPropertyData(deviceID, &propAddress, 0, nil, &size, ptr)
        }
        guard status == noErr, let raw = name else { return nil }
        return raw.takeRetainedValue() as String
    }

    /// Returns `true` if the device has any input streams (is a microphone).
    private static func isAudioInputDevice(_ deviceID: AudioDeviceID) -> Bool {
        var propAddress = AudioObjectPropertyAddress(
            mSelector: kAudioDevicePropertyStreamConfiguration,
            mScope:    kAudioObjectPropertyScopeInput,
            mElement:  kAudioObjectPropertyElementMain
        )
        var dataSize: UInt32 = 0
        guard AudioObjectGetPropertyDataSize(
            deviceID, &propAddress, 0, nil, &dataSize
        ) == noErr, dataSize >= MemoryLayout<UInt32>.size else { return false }

        let buffer = UnsafeMutableRawPointer.allocate(
            byteCount:  Int(dataSize),
            alignment:  MemoryLayout<UInt32>.alignment
        )
        defer { buffer.deallocate() }

        var outSize = dataSize
        guard AudioObjectGetPropertyData(
            deviceID, &propAddress, 0, nil, &outSize, buffer
        ) == noErr else { return false }

        let mNumberBuffers = buffer.load(as: UInt32.self)
        return mNumberBuffers > 0
    }
}

// MARK: - CaptureProcessScanner

/// Resolves device-client evidence where public APIs provide it and otherwise
/// records only foreground application context. The deprecated process-recency
/// scanner remains solely for source compatibility and is not used for capture
/// attribution.
enum CaptureProcessScanner: Sendable {

    /// Returns the exclusive CMIO owner when the device publishes one. A PID
    /// obtained from this property is device evidence, not a process-list guess.
    static func cameraOwner(deviceID: CMIODeviceID) -> DetectedCaptureProcess? {
        var address = CMIOObjectPropertyAddress(
            mSelector: CMIOObjectPropertySelector(kCMIODevicePropertyHogMode),
            mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
            mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain)
        )
        guard CMIOObjectHasProperty(deviceID, &address) else { return nil }
        var pid: pid_t = -1
        var size = UInt32(MemoryLayout<pid_t>.size)
        guard CMIOObjectGetPropertyData(
            deviceID, &address, 0, nil, size, &size, &pid
        ) == noErr, pid > 0 else { return nil }
        return process(pid: pid, confidence: "authoritative")
    }

    /// CoreAudio's public Process objects identify clients with active input IO.
    /// Match both the running-input bit and the device list to avoid attributing
    /// an unrelated audio client to the microphone transition.
    static func microphoneOwner(deviceID: AudioDeviceID) -> DetectedCaptureProcess? {
        var address = AudioObjectPropertyAddress(
            mSelector: kAudioHardwarePropertyProcessObjectList,
            mScope: kAudioObjectPropertyScopeGlobal,
            mElement: kAudioObjectPropertyElementMain
        )
        var byteCount: UInt32 = 0
        guard AudioObjectGetPropertyDataSize(
            AudioObjectID(kAudioObjectSystemObject), &address, 0, nil, &byteCount
        ) == noErr, byteCount > 0 else { return nil }

        var objects = [AudioObjectID](
            repeating: kAudioObjectUnknown,
            count: Int(byteCount) / MemoryLayout<AudioObjectID>.size
        )
        guard AudioObjectGetPropertyData(
            AudioObjectID(kAudioObjectSystemObject), &address, 0, nil, &byteCount, &objects
        ) == noErr else { return nil }

        for object in objects where audioProcessIsUsingInput(object, deviceID: deviceID) {
            var pidAddress = AudioObjectPropertyAddress(
                mSelector: kAudioProcessPropertyPID,
                mScope: kAudioObjectPropertyScopeGlobal,
                mElement: kAudioObjectPropertyElementMain
            )
            var pid: pid_t = 0
            var pidSize = UInt32(MemoryLayout<pid_t>.size)
            if AudioObjectGetPropertyData(
                object, &pidAddress, 0, nil, &pidSize, &pid
            ) == noErr, let resolved = process(pid: pid, confidence: "authoritative") {
                return resolved
            }
        }
        return nil
    }

    /// Public camera APIs do not always publish a client PID. In that case,
    /// preserve useful context without claiming ownership.
    @MainActor
    static func frontmostContext() -> DetectedCaptureProcess? {
        guard let app = NSWorkspace.shared.frontmostApplication,
              app.processIdentifier != ProcessInfo.processInfo.processIdentifier,
              let path = app.executableURL?.path,
              !path.isEmpty else { return nil }
        let signing = SignatureValidator.shared.evaluate(binaryPath: path)
        guard !signing.isSuspicious else { return nil }
        return DetectedCaptureProcess(
            pid: app.processIdentifier,
            name: app.localizedName ?? (path as NSString).lastPathComponent,
            path: path,
            signingStatus: signing,
            confidence: "contextual"
        )
    }

    private static func audioProcessIsUsingInput(
        _ object: AudioObjectID,
        deviceID: AudioDeviceID
    ) -> Bool {
        var runningAddress = AudioObjectPropertyAddress(
            mSelector: kAudioProcessPropertyIsRunningInput,
            mScope: kAudioObjectPropertyScopeGlobal,
            mElement: kAudioObjectPropertyElementMain
        )
        var running: UInt32 = 0
        var runningSize = UInt32(MemoryLayout<UInt32>.size)
        guard AudioObjectGetPropertyData(
            object, &runningAddress, 0, nil, &runningSize, &running
        ) == noErr, running != 0 else { return false }

        var devicesAddress = AudioObjectPropertyAddress(
            mSelector: kAudioProcessPropertyDevices,
            mScope: kAudioObjectPropertyScopeInput,
            mElement: kAudioObjectPropertyElementMain
        )
        var devicesSize: UInt32 = 0
        guard AudioObjectGetPropertyDataSize(
            object, &devicesAddress, 0, nil, &devicesSize
        ) == noErr, devicesSize > 0 else { return false }
        var devices = [AudioObjectID](
            repeating: kAudioObjectUnknown,
            count: Int(devicesSize) / MemoryLayout<AudioObjectID>.size
        )
        guard AudioObjectGetPropertyData(
            object, &devicesAddress, 0, nil, &devicesSize, &devices
        ) == noErr else { return false }
        return devices.contains(deviceID)
    }

    private static func process(pid: pid_t, confidence: String) -> DetectedCaptureProcess? {
        guard let info = ProcessScanner.quickInfo(pid: pid) else { return nil }
        let signing = info.path.isEmpty
            ? SigningStatus.unknown
            : SignatureValidator.shared.evaluate(binaryPath: info.path)
        let name = NSRunningApplication(processIdentifier: pid)?.localizedName
            ?? info.name
        return DetectedCaptureProcess(
            pid: pid,
            name: name,
            path: info.path,
            signingStatus: signing,
            confidence: confidence
        )
    }

    /// Returns the most likely process currently accessing a capture device.
    @available(*, deprecated, message: "Process-list recency is not capture ownership evidence")
    static func detectAccessingProcess() -> DetectedCaptureProcess? {
        guard let snapshots = listRunningProcesses(), !snapshots.isEmpty else { return nil }

        let systemNamePrefixes = [
            "kernel_task", "launchd", "VDCAssistant", "avconferencedd",
            "appleh13camerad", "coreaudiod", "audioprocd", "sysmond",
            "trustd", "configd", "distnoted", "notifyd", "rapportd"
        ]

        let candidates = snapshots
            .filter { snap in
                !systemNamePrefixes.contains(where: { snap.name.hasPrefix($0) })
                && snap.pid > 500
                && !snap.path.hasPrefix("/usr/libexec")
                && !snap.path.hasPrefix("/System/Library")
            }
            .sorted { ($0.startTime ?? .distantPast) > ($1.startTime ?? .distantPast) }

        guard let top = candidates.first else { return nil }

        let signing: SigningStatus = top.path.isEmpty
            ? .unknown
            : SignatureValidator.shared.evaluate(binaryPath: top.path)

        return DetectedCaptureProcess(
            pid:           top.pid,
            name:          top.name,
            path:          top.path,
            signingStatus: signing
        )
    }

    // MARK: - Private

    private struct ProcessSnapshot {
        let pid:       Int32
        let name:      String
        let path:      String
        let startTime: Date?
    }

    private static func listRunningProcesses() -> [ProcessSnapshot]? {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        var size = 0
        guard sysctl(&mib, 4, nil, &size, nil, 0) == 0, size > 0 else { return nil }

        let count = size / MemoryLayout<kinfo_proc>.stride
        var procs = [kinfo_proc](repeating: kinfo_proc(), count: count)
        guard sysctl(&mib, 4, &procs, &size, nil, 0) == 0 else { return nil }

        return procs.compactMap { kp -> ProcessSnapshot? in
            let pid = kp.kp_proc.p_pid
            guard pid > 0 else { return nil }

            let name = processName(from: kp)
            guard !name.isEmpty else { return nil }

            let path = processPath(for: pid)

            let tv = kp.kp_proc.p_starttime
            let startTime: Date? = tv.tv_sec > 0
                ? Date(timeIntervalSince1970: TimeInterval(tv.tv_sec))
                : nil

            return ProcessSnapshot(pid: pid, name: name, path: path, startTime: startTime)
        }
    }

    private static func processName(from kp: kinfo_proc) -> String {
        var comm = kp.kp_proc.p_comm
        return withUnsafeBytes(of: &comm) { bytes in
            let utf8 = bytes.prefix(while: { $0 != 0 })
            return String(decoding: utf8, as: UTF8.self)
        }
    }

    private static func processPath(for pid: Int32) -> String {
        var pathBuf = [Int8](repeating: 0, count: Int(MAXPATHLEN))
        proc_pidpath(pid, &pathBuf, UInt32(pathBuf.count))
        let bytes = pathBuf.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }
        return String(decoding: bytes, as: UTF8.self)
    }
}
