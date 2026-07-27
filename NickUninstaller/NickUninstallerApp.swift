import SwiftUI

@main
struct NickUninstallerApp: App {
    var body: some Scene {
        Window("Nick Uninstaller", id: "uninstaller") {
            UninstallerView()
                .frame(minWidth: 680, minHeight: 440)
        }
        .windowResizability(.contentMinSize)
        .defaultSize(width: 720, height: 480)
    }
}
