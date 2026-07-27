#!/usr/bin/swift

import AppKit
import Foundation

guard CommandLine.arguments.count == 3 else {
    fputs("usage: make-dmg-background.swift <app-icon.png> <output.png>\n", stderr)
    exit(2)
}

let iconURL = URL(fileURLWithPath: CommandLine.arguments[1])
let outputURL = URL(fileURLWithPath: CommandLine.arguments[2])
let size = NSSize(width: 720, height: 440)
guard let bitmap = NSBitmapImageRep(
    bitmapDataPlanes: nil,
    pixelsWide: Int(size.width),
    pixelsHigh: Int(size.height),
    bitsPerSample: 8,
    samplesPerPixel: 4,
    hasAlpha: true,
    isPlanar: false,
    colorSpaceName: .deviceRGB,
    bytesPerRow: 0,
    bitsPerPixel: 0
) else {
    fputs("Could not create DMG background bitmap.\n", stderr)
    exit(1)
}
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: bitmap)
defer { NSGraphicsContext.restoreGraphicsState() }

let rect = NSRect(origin: .zero, size: size)
let gradient = NSGradient(
    starting: NSColor(calibratedRed: 0.055, green: 0.071, blue: 0.090, alpha: 1),
    ending: NSColor(calibratedRed: 0.025, green: 0.031, blue: 0.043, alpha: 1)
)!
gradient.draw(in: rect, angle: -90)

NSColor(calibratedWhite: 1, alpha: 0.06).setStroke()
let border = NSBezierPath(roundedRect: rect.insetBy(dx: 1, dy: 1), xRadius: 18, yRadius: 18)
border.lineWidth = 1
border.stroke()

if let icon = NSImage(contentsOf: iconURL) {
    icon.draw(
        in: NSRect(x: 312, y: 318, width: 96, height: 96),
        from: .zero,
        operation: .sourceOver,
        fraction: 1
    )
}

let centered = NSMutableParagraphStyle()
centered.alignment = .center

func draw(_ text: String, y: CGFloat, font: NSFont, color: NSColor) {
    text.draw(
        in: NSRect(x: 40, y: y, width: 640, height: 40),
        withAttributes: [
            .font: font,
            .foregroundColor: color,
            .paragraphStyle: centered,
        ]
    )
}

draw(
    "Install Nick",
    y: 276,
    font: .systemFont(ofSize: 30, weight: .semibold),
    color: .white
)
draw(
    "Security and privacy protection for your Mac",
    y: 246,
    font: .systemFont(ofSize: 15, weight: .regular),
    color: NSColor(calibratedWhite: 0.76, alpha: 1)
)
draw(
    "Double-click the installer below",
    y: 90,
    font: .systemFont(ofSize: 15, weight: .medium),
    color: NSColor(calibratedRed: 0.34, green: 0.88, blue: 0.62, alpha: 1)
)
draw(
    "macOS will guide you through the required approvals.",
    y: 64,
    font: .systemFont(ofSize: 12, weight: .regular),
    color: NSColor(calibratedWhite: 0.58, alpha: 1)
)

guard let png = bitmap.representation(using: .png, properties: [:]) else {
    fputs("Could not render DMG background.\n", stderr)
    exit(1)
}
try png.write(to: outputURL, options: .atomic)
