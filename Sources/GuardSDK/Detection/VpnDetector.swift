import Foundation

enum VpnDetector {
    static func detect() -> DetectionResult? {
        // 네트워크 인터페이스에서 VPN (utun, ppp, ipsec) 확인
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else { return nil }
        defer { freeifaddrs(ifaddr) }

        var ptr = firstAddr
        while true {
            let name = String(cString: ptr.pointee.ifa_name)
            if name.hasPrefix("utun") || name.hasPrefix("ppp") || name.hasPrefix("ipsec") {
                return DetectionResult(type: .vpn, severity: .low, details: ["interface": name])
            }
            guard let next = ptr.pointee.ifa_next else { break }
            ptr = next
        }

        return nil
    }
}
