// MARK: - Nick
// Copyright © 2026 Ehsan Azish — github.com/EhsanAzish80
// Licensed under AGPL-3.0. See LICENSE for details.

import CoreML
import Foundation
import Security

// MARK: - ThreatPredictor

/// Scores an executable **before it runs** using static feature analysis.
///
/// **v3.0 strategy:** heuristic engine (no trained model required).
/// A Core ML `.mlmodelc` bundle can be dropped into the extension without
/// code changes — if absent, the heuristic fallback is used automatically.
///
/// **Performance contract:** must complete in <50 ms — this runs on the
/// AUTH_EXEC path. File reads are capped at `maxReadBytes` to honour that.
final class ThreatPredictor {

    // MARK: - Types

    struct PredictionInput {
        let fileSize: Int
        let entropy: Double
        let isSigned: Bool
        let suspiciousAPICount: Int
        let obfuscationScore: Double
        let hasNetworkStrings: Bool
        let hasEncryptionStrings: Bool
        let stringCount: Int
    }

    struct PredictionResult {
        let threatProbability: Double   // 0.0–1.0
        let classification: Classification
        let confidence: Double          // 0.0 = uncertain, 1.0 = certain

        enum Classification: String {
            case benign, pup, suspicious, malware
        }
    }

    // MARK: - Configuration

    /// Maximum bytes read from a file for feature extraction.
    /// Keeps AUTH_EXEC latency low even for very large binaries.
    private let maxReadBytes = 512 * 1024   // 512 KB

    // MARK: - Private

    private var model: MLModel?

    // MARK: - Init

    init() {
        loadModel()
    }

    // MARK: - Public API

    /// Predicts whether `filePath` is a threat.
    ///
    /// - Returns: `nil` if the file cannot be read (e.g. it was deleted before
    ///   the AUTH_EXEC fired), otherwise a `PredictionResult`.
    func predict(filePath: String) -> PredictionResult? {
        guard let features = extractFeatures(from: filePath) else { return nil }

        if let model {
            return coreMLPredict(features: features, model: model)
        }
        return heuristicPredict(features: features)
    }

    // MARK: - Feature Extraction

    private func extractFeatures(from filePath: String) -> PredictionInput? {
        let fm = FileManager.default
        guard let attrs = try? fm.attributesOfItem(atPath: filePath) else { return nil }
        let fileSize = (attrs[.size] as? Int) ?? 0

        // Read capped slice for analysis
        guard let fh = FileHandle(forReadingAtPath: filePath) else { return nil }
        let data = fh.readData(ofLength: maxReadBytes)
        try? fh.close()

        guard !data.isEmpty else { return nil }

        let entropy            = calculateEntropy(data: data)
        let strings            = extractStrings(data: data)
        let suspiciousAPICount = countSuspiciousAPIs(strings: strings)
        let hasNetworkStrings  = strings.contains(where: isNetworkString)
        let hasEncryptionStr   = strings.contains(where: isEncryptionString)
        let obfuscation        = estimateObfuscation(entropy: entropy, stringCount: strings.count,
                                                     dataSize: data.count)

        return PredictionInput(
            fileSize:           fileSize,
            entropy:            entropy,
            isSigned:           checkCodeSigning(path: filePath),
            suspiciousAPICount: suspiciousAPICount,
            obfuscationScore:   obfuscation,
            hasNetworkStrings:  hasNetworkStrings,
            hasEncryptionStrings: hasEncryptionStr,
            stringCount:        strings.count
        )
    }

    // MARK: - Core ML Path

    private func coreMLPredict(features: PredictionInput, model: MLModel) -> PredictionResult {
        do {
            let input = try MLMultiArray(shape: [8], dataType: .double)
            input[0] = NSNumber(value: Double(features.fileSize))
            input[1] = NSNumber(value: features.entropy)
            input[2] = NSNumber(value: features.isSigned ? 1.0 : 0.0)
            input[3] = NSNumber(value: Double(features.suspiciousAPICount))
            input[4] = NSNumber(value: features.obfuscationScore)
            input[5] = NSNumber(value: features.hasNetworkStrings ? 1.0 : 0.0)
            input[6] = NSNumber(value: features.hasEncryptionStrings ? 1.0 : 0.0)
            input[7] = NSNumber(value: Double(features.stringCount))

            let provider = try MLDictionaryFeatureProvider(
                dictionary: ["features": MLFeatureValue(multiArray: input)]
            )
            let prediction = try model.prediction(from: provider)
            let prob = prediction.featureValue(for: "threatProbability")?.doubleValue ?? 0.0
            return PredictionResult(
                threatProbability: prob,
                classification: classifyFromProbability(prob),
                confidence: abs(prob - 0.5) * 2.0
            )
        } catch {
            return heuristicPredict(features: features)
        }
    }

    // MARK: - Heuristic Path (v3.0 MVP)

    private func heuristicPredict(features: PredictionInput) -> PredictionResult {
        var score = 0.0

        if !features.isSigned                                        { score += 0.20 }
        if features.entropy > 7.0                                    { score += 0.20 }
        if features.suspiciousAPICount > 3                           { score += 0.20 }
        if features.obfuscationScore > 0.5                           { score += 0.20 }
        if features.hasNetworkStrings && !features.isSigned          { score += 0.10 }
        if features.hasEncryptionStrings && features.entropy > 7.0   { score += 0.10 }

        let capped = min(score, 1.0)
        return PredictionResult(
            threatProbability: capped,
            classification:    classifyFromProbability(capped),
            confidence:        0.5   // lower confidence for heuristic
        )
    }

    // MARK: - Analysis Helpers

    private func calculateEntropy(data: Data) -> Double {
        var frequency = [UInt8: Int]()
        for byte in data { frequency[byte, default: 0] += 1 }
        let length = Double(data.count)
        var entropy = 0.0
        for (_, count) in frequency {
            let p = Double(count) / length
            if p > 0 { entropy -= p * log2(p) }
        }
        return entropy
    }

    private func extractStrings(data: Data, minLength: Int = 6) -> [String] {
        var strings: [String] = []
        var current = ""
        for byte in data {
            if byte >= 0x20 && byte < 0x7F {
                current.append(Character(UnicodeScalar(byte)))
            } else {
                if current.count >= minLength { strings.append(current) }
                current = ""
            }
        }
        if current.count >= minLength { strings.append(current) }
        return strings
    }

    private let suspiciousAPIs: Set<String> = [
        "dlopen", "dlsym", "ptrace", "task_for_pid",
        "NSCreateObjectFileImageFromMemory", "NSAppleScript",
        "IORegistryEntryCreateCFProperty", "kext_request",
        "SecKeychainFindGenericPassword",
        "system(", "popen(", "exec(", "fork(",
    ]

    private func countSuspiciousAPIs(strings: [String]) -> Int {
        strings.filter { str in suspiciousAPIs.contains(where: { str.contains($0) }) }.count
    }

    private func isNetworkString(_ s: String) -> Bool {
        let patterns = ["http://", "https://", "ftp://", "socket(", "connect("]
        if patterns.contains(where: { s.contains($0) }) { return true }
        return s.range(of: #"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"#,
                       options: .regularExpression) != nil
    }

    private func isEncryptionString(_ s: String) -> Bool {
        let keywords = ["AES", "RSA", "encrypt", "decrypt", "cipher", "base64"]
        return keywords.contains(where: { s.localizedCaseInsensitiveContains($0) })
    }

    private func estimateObfuscation(entropy: Double, stringCount: Int, dataSize: Int) -> Double {
        let density = Double(stringCount) / max(Double(dataSize), 1.0) * 1_000
        if entropy > 7.5 && density < 0.5 { return 0.9 }
        if entropy > 7.0 && density < 1.0 { return 0.6 }
        if entropy > 6.5                   { return 0.3 }
        return 0.1
    }

    private func checkCodeSigning(path: String) -> Bool {
        var staticCode: SecStaticCode?
        let url = URL(fileURLWithPath: path) as CFURL
        guard SecStaticCodeCreateWithPath(url, [], &staticCode) == errSecSuccess,
              let code = staticCode else { return false }
        return SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: 0), nil) == errSecSuccess
    }

    private func classifyFromProbability(_ prob: Double) -> PredictionResult.Classification {
        switch prob {
        case 0.0..<0.2: return .benign
        case 0.2..<0.5: return .pup
        case 0.5..<0.8: return .suspicious
        default:        return .malware
        }
    }

    // MARK: - Model Loading

    private func loadModel() {
        guard let url = Bundle.main.url(forResource: "ThreatClassifier", withExtension: "mlmodelc")
        else {
            // No model bundled yet — heuristic fallback will be used (v3.0 MVP)
            return
        }
        model = try? MLModel(contentsOf: url)
    }
}
