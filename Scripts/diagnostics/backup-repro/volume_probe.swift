import Foundation

// Read metadata and construct, but never iterate, an enumerator. No Nick calls.
let path = CommandLine.arguments.dropFirst().first ?? ""
guard path.hasPrefix("/Volumes/NickRepro-") else { fatalError("Expected harness mount") }
let url = URL(fileURLWithPath: path)
var result: [String: Any] = ["path": path, "time": Date().timeIntervalSince1970]
do {
    let values = try url.resourceValues(forKeys: [.volumeIsLocalKey, .volumeIsRemovableKey, .volumeIsEjectableKey])
    result["volumeIsLocal"] = values.volumeIsLocal ?? false
    result["volumeIsRemovable"] = values.volumeIsRemovable ?? false
    result["volumeIsEjectable"] = values.volumeIsEjectable ?? false
    result["sameEligibilityPredicate"] = values.volumeIsLocal == true && (values.volumeIsRemovable == true || values.volumeIsEjectable == true)
} catch { result["metadataError"] = String(describing: error) }
let enumerator = FileManager.default.enumerator(at: url,
    includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .isSymbolicLinkKey, .isDirectoryKey, .isExecutableKey], options: [])
result["enumeratorCreated"] = enumerator != nil
let data = try JSONSerialization.data(withJSONObject: result, options: [.sortedKeys])
print(String(decoding: data, as: UTF8.self))
