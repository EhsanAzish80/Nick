import Darwin
import Foundation

enum ProcessPipeResolver {
    static func identifiers(pid: Int32) -> Set<UInt64> {
        let byteCount = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
        guard byteCount > 0 else { return [] }
        let count = Int(byteCount) / MemoryLayout<proc_fdinfo>.stride
        var descriptors = Array(repeating: proc_fdinfo(), count: count)
        let readCount = descriptors.withUnsafeMutableBytes { buffer in
            proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buffer.baseAddress, Int32(buffer.count))
        }
        guard readCount > 0 else { return [] }

        return Set(descriptors.prefix(Int(readCount) / MemoryLayout<proc_fdinfo>.stride).compactMap { descriptor in
            guard descriptor.proc_fdtype == PROX_FDTYPE_PIPE else { return nil }
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
            guard result == MemoryLayout<pipe_fdinfo>.size else { return nil }
            return UInt64(info.pipeinfo.pipe_stat.vst_ino)
        })
    }
}
