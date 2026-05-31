// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// MARK: - JunkCategory

/// Top-level grouping for scan-rule results displayed in the performance UI.
enum JunkCategory: String, Codable, Sendable, CaseIterable, Identifiable {

    case developerCache      = "developerCache"
    case simulatorData       = "simulatorData"
    case iosBackups          = "iosBackups"
    case deviceSupport       = "deviceSupport"
    case xcodeArchives        = "xcodeArchives"
    case documentation       = "documentation"
    case homebrew            = "homebrew"
    case scriptingCaches     = "scriptingCaches"
    case androidGradleCache  = "androidGradleCache"
    case browserCache        = "browserCache"
    case logs                = "logs"
    case installers          = "installers"
    case downloads           = "downloads"
    case trash               = "trash"
    case largeFiles          = "largeFiles"
    case duplicates          = "duplicates"
    case meetingRecordings   = "meetingRecordings"
    case screenRecordings    = "screenRecordings"
    case applicationCaches   = "applicationCaches"
    case messagesAttachments = "messagesAttachments"
    case docker              = "docker"
    case hugeFolders         = "hugeFolders"
    case other               = "other"

    public var id: String { rawValue }

    var displayName: String {
        switch self {
        case .developerCache:      return "Developer Caches"
        case .simulatorData:       return "Simulator Data"
        case .iosBackups:          return "iOS Backups"
        case .deviceSupport:       return "Device Support Files"
        case .xcodeArchives:       return "Xcode Archives"
        case .documentation:       return "Xcode Documentation"
        case .homebrew:            return "Homebrew Cache"
        case .scriptingCaches:     return "Script & Package Caches"
        case .androidGradleCache:  return "Android/Gradle Cache"
        case .browserCache:        return "Browser Cache"
        case .logs:                return "Log Files"
        case .installers:          return "Old Installers"
        case .downloads:           return "Large Downloads"
        case .trash:               return "Trash"
        case .largeFiles:          return "Large Forgotten Files"
        case .duplicates:          return "Duplicate Files"
        case .meetingRecordings:   return "Meeting Recordings"
        case .screenRecordings:    return "Screen Recordings"
        case .applicationCaches:   return "Application Caches"
        case .messagesAttachments: return "Messages Attachments"
        case .docker:              return "Docker Data"
        case .hugeFolders:         return "Huge Folders"
        case .other:               return "Other"
        }
    }

    var systemImage: String {
        switch self {
        case .developerCache:      return "hammer.circle"
        case .simulatorData:       return "iphone.gen3"
        case .iosBackups:          return "externaldrive.badge.icloud"
        case .deviceSupport:       return "cable.connector"
        case .xcodeArchives:       return "archivebox"
        case .documentation:       return "doc.text.magnifyingglass"
        case .homebrew:            return "mug"
        case .scriptingCaches:     return "terminal"
        case .androidGradleCache:  return "puzzlepiece"
        case .browserCache:        return "network.badge.shield.half.filled"
        case .logs:                return "doc.text"
        case .installers:          return "arrow.down.to.line.circle"
        case .downloads:           return "arrow.down.circle"
        case .trash:               return "trash"
        case .largeFiles:          return "doc.badge.ellipsis"
        case .duplicates:          return "doc.on.doc"
        case .meetingRecordings:   return "video.circle"
        case .screenRecordings:    return "menubar.dock.rectangle.badge.record"
        case .applicationCaches:   return "app.badge"
        case .messagesAttachments: return "bubble.left.and.bubble.right"
        case .docker:              return "shippingbox"
        case .hugeFolders:         return "folder.badge.minus"
        case .other:               return "ellipsis.circle"
        }
    }
}
