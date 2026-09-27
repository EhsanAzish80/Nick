// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import AppKit
import SwiftUI

// MARK: - Motion tokens

/// Simple Home motion. Every animation returns `nil` under Reduce Motion, so
/// changes still happen, just without movement.
enum HomeMotion {
    static let stateChange: Animation = .smooth(duration: 0.35)
    static let entrance: Animation = .easeOut(duration: 0.25)
    static let entranceStagger: Double = 0.04
    static let hover: Animation = .snappy
    /// One full in-and-out breath of the protected ring.
    static let breathPeriod: Double = 8

    static func animation(_ animation: Animation, reduceMotion: Bool) -> Animation? {
        reduceMotion ? nil : animation
    }

    /// 0…1…0 over `breathPeriod`, eased (a cosine is ease-in-out).
    static func breathPhase(at date: Date) -> Double {
        let t = date.timeIntervalSinceReferenceDate
            .truncatingRemainder(dividingBy: breathPeriod) / breathPeriod
        return (1 - cos(t * 2 * .pi)) / 2
    }
}

/// The hero and cards fade up once per launch, the first time Home appears.
@MainActor
enum HomeEntrance {
    static var hasRun = false
}

// MARK: - Fade-up entrance

private struct FadeUp: ViewModifier {
    let visible: Bool
    let index: Int
    let reduceMotion: Bool

    func body(content: Content) -> some View {
        content
            .opacity(visible ? 1 : 0)
            .offset(y: visible ? 0 : 8)
            .animation(
                HomeMotion.animation(
                    HomeMotion.entrance.delay(Double(index) * HomeMotion.entranceStagger),
                    reduceMotion: reduceMotion
                ),
                value: visible
            )
    }
}

extension View {
    func homeFadeUp(visible: Bool, index: Int, reduceMotion: Bool) -> some View {
        modifier(FadeUp(visible: visible, index: index, reduceMotion: reduceMotion))
    }
}

// MARK: - Window visibility

/// Reports whether the hosting window is actually on screen (not occluded,
/// minimised or ordered out), so looping motion can stop when nobody sees it.
struct WindowVisibilityReader: NSViewRepresentable {
    let onChange: (Bool) -> Void

    func makeNSView(context: Context) -> ObserverView {
        let view = ObserverView()
        view.onChange = onChange
        return view
    }

    func updateNSView(_ view: ObserverView, context: Context) {
        view.onChange = onChange
    }

    final class ObserverView: NSView {
        var onChange: ((Bool) -> Void)?
        private var tokens: [NSObjectProtocol] = []

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            for token in tokens { NotificationCenter.default.removeObserver(token) }
            tokens.removeAll()
            guard let window else {
                onChange?(false)
                return
            }
            let names: [Notification.Name] = [
                NSWindow.didChangeOcclusionStateNotification,
                NSWindow.didMiniaturizeNotification,
                NSWindow.didDeminiaturizeNotification,
            ]
            for name in names {
                tokens.append(NotificationCenter.default.addObserver(
                    forName: name, object: window, queue: .main
                ) { [weak self] _ in
                    MainActor.assumeIsolated { self?.report() }
                })
            }
            report()
        }

        private func report() {
            guard let window else { return }
            onChange?(window.occlusionState.contains(.visible) && !window.isMiniaturized)
        }

        override func hitTest(_ point: NSPoint) -> NSView? { nil }
    }
}
