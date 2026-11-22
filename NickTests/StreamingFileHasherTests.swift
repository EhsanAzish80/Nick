import CryptoKit
import Darwin
import XCTest
@testable import Nick

final class StreamingFileHasherTests: XCTestCase {
    func testDigestsAndByteAccountingAtChunkBoundaries() throws {
        let directory = temporaryDirectory()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let chunk = StreamingFileHasher.chunkSize
        for size in [0, 1, chunk - 1, chunk, chunk + 1, 2 * chunk + 1, 12 * chunk] {
            try autoreleasepool {
                let data = Data(repeating: 0x61, count: size)
                let url = directory.appendingPathComponent("fixture-\(size).bin")
                try data.write(to: url)
                let expected = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
                var bytes = 0, largestRead = 0
                let actual = StreamingFileHasher.sha256(path: url.path) { count in
                    bytes += count
                    largestRead = max(largestRead, count)
                }
                XCTAssertEqual(actual, expected, "size \(size)")
                XCTAssertEqual(bytes, size)
                XCTAssertLessThanOrEqual(largestRead, chunk)
            }
        }
    }

    func testMissingFileDoesNotHashOrAccountBytes() {
        var bytes = 0
        XCTAssertNil(StreamingFileHasher.sha256(path: temporaryDirectory().path) { bytes += $0 })
        XCTAssertEqual(bytes, 0)
    }

    func testRepeatedLargeHashesDoNotRetainReadBuffersUntilOuterPoolEnds() throws {
        let directory = temporaryDirectory()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("large-hash-fixture.bin")
        let expected: String = try autoreleasepool {
            let block = Data(repeating: 0x61, count: StreamingFileHasher.chunkSize)
            FileManager.default.createFile(atPath: url.path, contents: nil)
            let writer = try FileHandle(forWritingTo: url)
            defer { try? writer.close() }
            var digest = SHA256()
            for _ in 0..<48 {
                try writer.write(contentsOf: block)
                digest.update(data: block)
            }
            return digest.finalize().map { String(format: "%02x", $0) }.joined()
        }

        // One outer pool deliberately spans all six reads (288 MiB). Without
        // the production inner pool, the Foundation buffers accumulate here.
        autoreleasepool {
            let before = liveMallocBytes()
            var peak = before, bytes = 0
            for _ in 0..<6 {
                XCTAssertEqual(StreamingFileHasher.sha256(path: url.path) { count in
                    bytes += count
                    peak = max(peak, liveMallocBytes())
                }, expected)
            }
            XCTAssertEqual(bytes, 288 * 1_024 * 1_024)
            XCTAssertLessThan(peak >= before ? peak - before : 0, 64 * 1_024 * 1_024,
                              "Streaming buffers must be released inside the chunk loop")
        }
    }

    private func liveMallocBytes() -> UInt64 {
        var statistics = malloc_statistics_t()
        malloc_zone_statistics(nil, &statistics)
        return UInt64(statistics.size_in_use)
    }

    private func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory.appendingPathComponent("NickHashTests-\(UUID().uuidString)")
    }
}
