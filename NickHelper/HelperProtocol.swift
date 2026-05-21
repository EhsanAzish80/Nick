import Foundation

/// XPC protocol exposed by the privileged helper to the main app.
@objc protocol NickHelperProtocol {

    /// Returns the SIP (System Integrity Protection) status.
    func getSIPStatus(reply: @escaping (Bool) -> Void)

    /// Returns the Application Firewall enabled state.
    func getFirewallStatus(reply: @escaping (Bool) -> Void)

    /// Reads a plist file at a privileged path.
    func readPlist(at path: String, reply: @escaping (Data?, Error?) -> Void)

    /// Returns a list of listening ports with associated process names.
    func getListeningPorts(reply: @escaping ([String: Int32]) -> Void)
}

/// Mach service name used to register/look up the helper.
let NickHelperMachServiceName = "com.ehsanazish.nick.helper"
