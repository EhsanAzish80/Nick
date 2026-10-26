import Darwin
import Foundation

enum ProcessPipeResolver {
    struct Evidence: Equatable, Sendable {
        let pipeIdentifiers: Set<UInt64>
        let standardInputPipeIdentifier: UInt64?
        let standardOutputPipeIdentifier: UInt64?
        let hasNetworkSocket: Bool

        static let empty = Self(
            pipeIdentifiers: [],
            standardInputPipeIdentifier: nil,
            standardOutputPipeIdentifier: nil,
            hasNetworkSocket: false
        )
    }

    static func identifiers(pid: Int32) -> Set<UInt64> {
        evidence(pid: pid).pipeIdentifiers
    }

    static func evidence(pid: Int32) -> Evidence {
        let byteCount = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard byteCount > 0 else { return .empty }
        let count = Int(byteCount) / MemoryLayout<proc_fdinfo>.stride
        var descriptors = Array(repeating: proc_fdinfo(), count: count)
        let readCount = descriptors.withUnsafeMutableBytes { buffer in
            proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buffer.baseAddress, Int32(buffer.count))
        }
        guard readCount > 0 else { return .empty }

        var pipes = Set<UInt64>()
        var standardInputPipe: UInt64?
        var standardOutputPipe: UInt64?
        var hasSocket = false
        for descriptor in descriptors.prefix(Int(readCount) / MemoryLayout<proc_fdinfo>.stride) {
            if descriptor.proc_fdtype == PROX_FDTYPE_SOCKET {
                var info = socket_fdinfo()
                let result = withUnsafeMutablePointer(to: &info) { pointer in
                    proc_pidfdinfo(
                        pid,
                        descriptor.proc_fd,
                        PROC_PIDFDSOCKETINFO,
                        pointer,
                        Int32(MemoryLayout<socket_fdinfo>.size)
                    )
                }
                if result == MemoryLayout<socket_fdinfo>.size,
                   info.psi.soi_family == AF_INET || info.psi.soi_family == AF_INET6 {
                    hasSocket = true
                }
                continue
            }
            guard descriptor.proc_fdtype == PROX_FDTYPE_PIPE else { continue }
            var info = pipe_fdinfo()
            let result = withUnsafeMutablePointer(to: &info) { pointer in
                proc_pidfdinfo(
                    pid,
                    descriptor.proc_fd,
                    PROC_PIDFDPIPEINFO,
                    pointer,
                    Int32(MemoryLayout<pipe_fdinfo>.size)
                )
            }
            guard result == MemoryLayout<pipe_fdinfo>.size else { continue }
            let identifier = UInt64(info.pipeinfo.pipe_stat.vst_ino)
            pipes.insert(identifier)
            if descriptor.proc_fd == STDIN_FILENO { standardInputPipe = identifier }
            if descriptor.proc_fd == STDOUT_FILENO { standardOutputPipe = identifier }
        }
        return Evidence(
            pipeIdentifiers: pipes,
            standardInputPipeIdentifier: standardInputPipe,
            standardOutputPipeIdentifier: standardOutputPipe,
            hasNetworkSocket: hasSocket
        )
    }
}
