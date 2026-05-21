import Foundation

// Entry point for the NickHelper privileged tool.
// Registered via SMAppService; launched on demand by the main app over XPC.

final class HelperDelegate: NSObject, NSXPCListenerDelegate, NickHelperProtocol {

    func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection connection: NSXPCConnection
    ) -> Bool {
        connection.exportedInterface = NSXPCInterface(with: NickHelperProtocol.self)
        connection.exportedObject = self
        connection.resume()
        return true
    }

    // MARK: - NickHelperProtocol

    func getSIPStatus(reply: @escaping (Bool) -> Void) {
        // TODO: Parse `csrutil status`
        reply(true)
    }

    func getFirewallStatus(reply: @escaping (Bool) -> Void) {
        // TODO: Read /Library/Preferences/com.apple.alf.plist
        reply(true)
    }

    func readPlist(at path: String, reply: @escaping (Data?, Error?) -> Void) {
        do {
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            reply(data, nil)
        } catch {
            reply(nil, error)
        }
    }

    func getListeningPorts(reply: @escaping ([String: Int32]) -> Void) {
        // TODO: Enumerate via sysctl
        reply([:])
    }
}

let delegate = HelperDelegate()
let listener = NSXPCListener(machServiceName: NickHelperMachServiceName)
listener.delegate = delegate
listener.resume()

RunLoop.main.run()
