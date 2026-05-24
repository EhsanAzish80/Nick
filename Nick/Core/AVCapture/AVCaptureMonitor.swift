// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AVFoundation
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
/// all CoreAudio input devices, comparing running state against a previously
/// recorded baseline.  A `ThreatSignal` is emitted only when a device transitions
/// from inactive → active, preventing duplicate alerts across successive scans.
///
/// Process attribution is performed on a background thread using sysctl: the most
/// recently launched non-system process is reported as the likely accessor.
/// Unsigned binaries are elevated to `.high` severity.
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

    /// Tracks device IDs → last-known running state to detect new activations.
    private var knownVideoState:  [CMIODeviceID:  Bool] = [:]
    private var knownAudioState:  [AudioDeviceID: Bool] = [:]

    private var deviceObservers: [NSObjectProtocol] = []

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

        // Only log when a camera or mic is actually active — avoids CMIO framework noise
        // on machines without supported camera hardware.
        if isCameraActive || isMicrophoneActive {
            Self.log.info("AVCapture scan — camera:\(self.isCameraActive) mic:\(self.isMicrophoneActive) signals:\(self.pendingSignals.count)")
        }
    }

    func stop() async {
        unregisterDeviceNotifications()
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
            let wasRunning = knownVideoState[deviceID] ?? false

            if running { anyRunning = true }

            if running && !wasRunning {
                let name    = CaptureDeviceAccessor.cmioDeviceName(deviceID) ?? "Camera"
                let process = await detectAccessingProcess()
                pendingSignals.append(
                    makeCaptureSignal(mediaType: "camera", deviceName: name, process: process)
                )
                Self.log.notice("Camera activated: \(name) — \(process?.name ?? "unknown")")
            }

            knownVideoState[deviceID] = running
        }

        isCameraActive = anyRunning
    }

    private func scanMicrophoneDevices() async {
        let deviceIDs = CaptureDeviceAccessor.audioInputDeviceIDs()
        var anyRunning = false

        for deviceID in deviceIDs {
            let running    = CaptureDeviceAccessor.isAudioDeviceRunning(deviceID)
            let wasRunning = knownAudioState[deviceID] ?? false

            if running { anyRunning = true }

            if running && !wasRunning {
                let name    = CaptureDeviceAccessor.audioDeviceName(deviceID) ?? "Microphone"
                let process = await detectAccessingProcess()
                pendingSignals.append(
                    makeCaptureSignal(mediaType: "microphone", deviceName: name, process: process)
                )
                Self.log.notice("Microphone activated: \(name) — \(process?.name ?? "unknown")")
            }

            knownAudioState[deviceID] = running
        }

        isMicrophoneActive = anyRunning
    }

    // MARK: - Process Detection

    private func detectAccessingProcess() async -> DetectedCaptureProcess? {
        await Task.detached(priority: .userInitiated) {
            CaptureProcessScanner.detectAccessingProcess()
        }.value
    }

    // MARK: - Signal Generation

    /// Builds a `ThreatSignal` for a capture-device activation event.
    ///
    /// Made `internal` for direct unit-test access.
    func makeCaptureSignal(
        mediaType:  String,
        deviceName: String,
        process:    DetectedCaptureProcess?
    ) -> ThreatSignal {
        let processName = process?.name ?? "unknown"

        let severity: SignalSeverity = {
            guard let p = process else { return .medium }
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

        return ThreatSignal(
            source:      .avCapture,
            severity:    severity,
            title:       "\(deviceName) activated by \(processName)",
            description: "The system \(mediaType) began streaming. " +
                         "Access attributed to '\(processName)'. " +
                         "Malware commonly activates cameras and microphones silently — " +
                         "verify this is expected.",
            context: ThreatSignalContext(
                processInfo: processInfo,
                metadata: [
                    "mediaType":  mediaType,
                    "deviceName": deviceName,
                    "process":    processName,
                    "reason":     "capture_device_active"
                ]
            )
        )
    }

    // MARK: - AVCaptureDevice Notifications

    private func registerDeviceNotifications() {
        let center = NotificationCenter.default

        let onConnect = center.addObserver(
            forName: AVCaptureDevice.wasConnectedNotification,
            object:  nil,
            queue:   .main
        ) { [weak self] _ in
            self?.handleDeviceConnected()
        }

        let onDisconnect = center.addObserver(
            forName: AVCaptureDevice.wasDisconnectedNotification,
            object:  nil,
            queue:   .main
        ) { [weak self] _ in
            self?.handleDeviceDisconnected()
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
}

// MARK: - DetectedCaptureProcess

/// Minimal process attribution captured at the time of device activation.
struct DetectedCaptureProcess: Sendable {
    let pid:           Int32
    let name:          String
    let path:          String
    let signingStatus: SigningStatus
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

/// Identifies the most likely user-space process accessing a capture device.
///
/// Uses `sysctl` to list running processes and returns the most recently started
/// non-system candidate.  Signing status is evaluated via `SignatureValidator`.
///
/// - Note: Attribution is best-effort; a future Endpoint Security integration
///         will provide authoritative access records.
enum CaptureProcessScanner: Sendable {

    /// Returns the most likely process currently accessing a capture device.
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

            // Process name from kp_proc.p_comm (fixed-size char tuple)
            var comm = kp.kp_proc.p_comm
            let commSize = MemoryLayout.size(ofValue: comm)
            let name = withUnsafeMutablePointer(to: &comm) { ptr in
                ptr.withMemoryRebound(to: UInt8.self, capacity: commSize) { uPtr in
                    let buf = UnsafeBufferPointer(start: uPtr, count: commSize)
                    return String(decoding: buf.prefix(while: { $0 != 0 }), as: UTF8.self)
                }
            }
            guard !name.isEmpty else { return nil }

            // Full path via proc_pidpath
            var pathBuf = [Int8](repeating: 0, count: Int(MAXPATHLEN))
            proc_pidpath(pid, &pathBuf, UInt32(pathBuf.count))
            let path = pathBuf.withUnsafeBufferPointer { bp in
                String(decoding: UnsafeRawBufferPointer(bp).prefix(while: { $0 != 0 }), as: UTF8.self)
            }

            let tv = kp.kp_proc.p_starttime
            let startTime: Date? = tv.tv_sec > 0
                ? Date(timeIntervalSince1970: TimeInterval(tv.tv_sec))
                : nil

            return ProcessSnapshot(pid: pid, name: name, path: path, startTime: startTime)
        }
    }
}
