import Foundation

enum JailbreakDetector {
    private static let knownPaths = [
        "/Applications/Cydia.app", "/Applications/Sileo.app", "/Applications/Zebra.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash", "/usr/sbin/sshd", "/etc/apt", "/var/lib/cydia",
        "/private/var/lib/apt/", "/var/jb", "/var/binpack",
    ]

    static func detect(signatures: [GuardSignature] = []) -> DetectionResult? {
        // 기본 경로 + 서버 시그니처 경로 합산
        var paths = knownPaths
        for sig in signatures where sig.checkMethod == "path" {
            paths.append(sig.value)
        }

        for path in paths {
            if FileManager.default.fileExists(atPath: path) {
                return DetectionResult(type: .jailbreak, severity: .high, details: ["path": path])
            }
        }

        // URL 스킴 체크
        let schemes = ["cydia://", "sileo://", "zbra://", "filza://"]
        let serverSchemes = signatures.filter { $0.checkMethod == "url_scheme" }.map { $0.value }
        for scheme in schemes + serverSchemes {
            if let url = URL(string: scheme), UIApplication.shared.canOpenURL(url) {
                return DetectionResult(type: .jailbreak, severity: .high, details: ["scheme": scheme])
            }
        }

        // 쓰기 가능 여부
        let testPath = "/private/jailbreak_test_\(UUID().uuidString)"
        if FileManager.default.createFile(atPath: testPath, contents: Data("test".utf8)) {
            try? FileManager.default.removeItem(atPath: testPath)
            return DetectionResult(type: .jailbreak, severity: .high, details: ["method": "writable_root"])
        }

        return nil
    }
}
