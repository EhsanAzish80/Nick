// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import Foundation

// Entry point for the NickHelper privileged tool.
// Registered via SMAppService; launched on demand by the main app over XPC.
//
// Security model: `HelperDaemon` validates every connection (team ID + rate limit)
// before handing it to `HelperProtocolImplementation`. See HelperDaemon.swift.

let daemon = HelperDaemon()
let listener = NSXPCListener(machServiceName: NickHelperMachServiceName)
listener.delegate = daemon
listener.resume()

RunLoop.main.run()
