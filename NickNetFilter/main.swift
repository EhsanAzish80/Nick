// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import NetworkExtension

// Standard entry point for a Network Extension System Extension.
// Registers FilterDataProvider as the content-filter provider and
// hands control to the NetworkExtension runtime.
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
