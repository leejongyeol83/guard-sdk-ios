import Foundation
import MachO

enum HookingDetector {
    private static let knownLibs = [
        "FridaGadget", "frida-agent", "libfrida", "libcycript",
        "MobileSubstrate", "libhooker", "substitute",
    ]

    static func detect(signatures: [GuardSignature] = []) -> DetectionResult? {
        var libs = knownLibs
        for sig in signatures where sig.checkMethod == "library" {
            libs.append(sig.value)
        }

        // dyld 이미지 검사
        let imageCount = _dyld_image_count()
        for i in 0..<imageCount {
            guard let name = _dyld_get_image_name(i) else { continue }
            let imageName = String(cString: name)
            for lib in libs {
                if imageName.contains(lib) {
                    return DetectionResult(type: .hooking, severity: .high, details: ["library": lib, "image": imageName])
                }
            }
        }

        // Frida 포트 체크 (27042)
        let portSignatures = signatures.filter { $0.checkMethod == "port" }
        for sig in portSignatures {
            if let port = UInt16(sig.value), isPortOpen(port) {
                return DetectionResult(type: .hooking, severity: .high, details: ["method": "port", "port": sig.value])
            }
        }

        return nil
    }

    private static func isPortOpen(_ port: UInt16) -> Bool {
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return false }
        defer { close(sock) }

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        return result == 0
    }
}
