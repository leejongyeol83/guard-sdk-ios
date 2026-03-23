// VpnDetector.swift
// Guard SDK - VPN 탐지기
//
// VPN 연결 상태를 탐지한다.
// iOS에서는 네트워크 인터페이스와 프록시 설정을 복합적으로 확인하여
// VPN 연결 여부를 판단한다.
//
// 주의: iOS는 시스템 내부적으로 utun 인터페이스를 사용하므로
// utun 존재만으로 VPN을 판단하면 오탐이 발생한다.
// 반드시 프록시 설정(SCOPED)과 함께 교차 검증해야 한다.
//
// 탐지 기법:
// 1. CFNetworkCopySystemProxySettings - VPN 프록시 설정 확인 (주 검사)
// 2. getifaddrs() - VPN 네트워크 인터페이스(ipsec, ppp, tap) 확인 (보조 검사)

import Foundation
#if canImport(Darwin)
import Darwin
#endif
#if canImport(CFNetwork)
import CFNetwork
#endif

/// VPN 연결 상태 탐지기.
///
/// 네트워크 인터페이스와 시스템 프록시 설정을 복합 확인하여
/// VPN 연결 여부를 탐지한다.
///
/// 탐지 판정:
/// - VPN 프록시 설정(SCOPED)이 감지되면 detected=true (주 기준)
/// - ipsec/ppp/tap 인터페이스가 있으면 detected=true (보조 기준)
/// - utun 단독으로는 탐지하지 않음 (iOS 시스템 인터페이스 오탐 방지)
class VpnDetector: Detector {

    let type: DetectionType = .vpn

    func detect() -> DetectionResult {
        var details: [String: String] = [:]

        // 검사 1: VPN 프록시 설정 확인 (주 검사 — 오탐 적음)
        let hasVpnConfig = checkVpnConfiguration()
        if hasVpnConfig {
            details["vpn_config"] = "VPN 프록시 설정 감지"
        }

        // 검사 2: VPN 전용 네트워크 인터페이스 확인 (ipsec/ppp/tap만, utun 제외)
        let hasVpnInterface = checkVpnOnlyInterfaces()
        if hasVpnInterface {
            details["vpn_interface"] = "VPN 전용 인터페이스(ipsec/ppp/tap) 감지"
        }

        // 검사 3: utun 인터페이스를 SCOPED와 교차 검증
        let hasUtunWithScoped = checkUtunWithScoped()
        if hasUtunWithScoped {
            details["vpn_utun"] = "VPN utun 인터페이스 + SCOPED 설정 감지"
        }

        // VPN 프록시 설정이 있거나, VPN 전용 인터페이스가 있거나, utun+SCOPED 교차 확인
        let detected = hasVpnConfig || hasVpnInterface || hasUtunWithScoped
        let confidence: Float = detected ? (hasVpnConfig && hasVpnInterface ? 1.0 : 0.7) : 0.0

        return DetectionResult(
            type: .vpn,
            detected: detected,
            confidence: confidence,
            details: details
        )
    }

    func isAvailable() -> Bool {
        return true
    }

    // MARK: - 검사 메서드

    /// VPN 전용 인터페이스를 확인하되, SCOPED 프록시와 교차 검증한다.
    ///
    /// iOS는 시스템 레벨에서 ipsec 인터페이스를 가질 수 있다
    /// (iCloud Private Relay, MDM 등). 인터페이스 존재만으로
    /// VPN을 판단하면 오탐이 발생하므로, SCOPED에 해당 인터페이스가
    /// 있는지 교차 확인한다. ppp/tap은 일반적으로 VPN 전용이다.
    ///
    /// - Returns: VPN 전용 인터페이스 존재 여부
    private func checkVpnOnlyInterfaces() -> Bool {
        var ifaddr: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else { return false }
        defer { freeifaddrs(ifaddr) }

        var foundInterfaces: [String] = []
        var current: UnsafeMutablePointer<ifaddrs> = firstAddr

        while true {
            let name = String(cString: current.pointee.ifa_name)
            let flags = Int32(current.pointee.ifa_flags)
            let isUp = (flags & IFF_UP) != 0

            // ppp/tap은 VPN 전용 — 존재하면 바로 탐지
            if isUp && (name.hasPrefix("ppp") || name.hasPrefix("tap")) {
                return true
            }
            // ipsec은 시스템에서도 사용할 수 있으므로 목록만 수집
            if isUp && name.hasPrefix("ipsec") {
                foundInterfaces.append(name)
            }

            guard let next = current.pointee.ifa_next else { break }
            current = next
        }

        // ipsec 인터페이스가 있으면 SCOPED 프록시와 교차 검증
        if !foundInterfaces.isEmpty {
            return verifyScopedContains(prefixes: ["ipsec"])
        }

        return false
    }

    /// SCOPED 프록시 설정에 특정 프리픽스 키가 있는지 확인한다.
    private func verifyScopedContains(prefixes: [String]) -> Bool {
        guard let cfDict = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any],
              let scoped = cfDict["__SCOPED__"] as? [String: Any] else {
            return false
        }

        return scoped.keys.contains(where: { key in
            prefixes.contains(where: { key.hasPrefix($0) })
        })
    }

    /// utun 인터페이스를 SCOPED 프록시 설정과 교차 검증한다.
    ///
    /// iOS는 시스템 내부에서 utun 인터페이스를 사용하므로,
    /// utun 존재만으로는 VPN을 판단할 수 없다.
    /// SCOPED 프록시 설정에 utun 키가 있을 때만 VPN으로 판단한다.
    ///
    /// - Returns: utun이 SCOPED에서도 확인되는지 여부
    private func checkUtunWithScoped() -> Bool {
        guard let cfDict = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any],
              let scoped = cfDict["__SCOPED__"] as? [String: Any] else {
            return false
        }

        return scoped.keys.contains(where: { $0.hasPrefix("utun") })
    }

    /// CFNetworkCopySystemProxySettings를 사용하여 VPN 프록시 설정을 확인한다.
    ///
    /// __SCOPED__ 딕셔너리 내에 VPN 관련 키(ipsec, ppp, tap 등)가
    /// 있으면 VPN이 활성화된 것으로 판단한다.
    /// utun은 교차 검증 메서드에서 별도로 처리한다.
    ///
    /// - Returns: VPN 프록시 설정 존재 여부
    private func checkVpnConfiguration() -> Bool {
        guard let cfDict = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any],
              let scoped = cfDict["__SCOPED__"] as? [String: Any] else {
            return false
        }

        // utun 제외 — VPN 전용 프록시 키만 확인
        let vpnKeys = ["tap", "tun", "ppp", "ipsec"]
        return scoped.keys.contains(where: { key in
            vpnKeys.contains(where: { key.hasPrefix($0) })
        })
    }
}
