// PolicyCache.swift
// Anti-Mobile Service iOS SDK - 보안 정책 로컬 캐시
//
// 서버에서 수신한 보안 정책을 로컬에 캐싱하여,
// 서버 통신 실패 시에도 마지막 유효한 정책으로 동작할 수 있게 한다.
// UserDefaults에 JSON 직렬화하여 저장하며, TTL 기반으로 만료를 관리한다.

import Foundation

// MARK: - 보안 정책 모델

/// 서버에서 전달되는 보안 정책 구조체.
///
/// 각 탐지 유형별로 활성화 여부와 탐지 시 수행할 액션을 정의한다.
/// Codable을 채택하여 JSON 직렬화/역직렬화를 지원한다.
public struct SecurityPolicy: Codable, Equatable {

    /// 정책 식별자 (서버에서 부여)
    public let policyId: String

    // MARK: - 탈옥 탐지 설정

    /// 탈옥 탐지 활성화 여부 (기본: true)
    public var jailbreakDetectionEnabled: Bool

    /// 탈옥 탐지 시 수행할 액션 (기본: "WARN")
    public var jailbreakDetectionAction: String

    // MARK: - 시뮬레이터 탐지 설정

    /// 시뮬레이터 탐지 활성화 여부 (기본: true)
    public var simulatorDetectionEnabled: Bool

    /// 시뮬레이터 탐지 시 수행할 액션 (기본: "WARN")
    public var simulatorDetectionAction: String

    // MARK: - 디버거 탐지 설정

    /// 디버거 탐지 활성화 여부 (기본: true)
    public var debuggerDetectionEnabled: Bool

    /// 디버거 탐지 시 수행할 액션 (기본: "WARN")
    public var debuggerDetectionAction: String

    // MARK: - 무결성 검증 설정

    /// 앱 무결성 검증 활성화 여부 (기본: true)
    public var integrityCheckEnabled: Bool

    /// 무결성 검증 실패 시 수행할 액션 (기본: "WARN")
    public var integrityCheckAction: String

    // MARK: - 후킹 탐지 설정

    /// 후킹 프레임워크 탐지 활성화 여부 (기본: true)
    public var hookingDetectionEnabled: Bool

    /// 후킹 탐지 시 수행할 액션 (기본: "WARN")
    public var hookingDetectionAction: String

    // MARK: - 서명 검증 설정

    /// 코드 서명 검증 활성화 여부 (기본: true)
    public var signatureVerifyEnabled: Bool

    /// 서명 검증 실패 시 수행할 액션 (기본: "WARN")
    public var signatureVerifyAction: String

    // MARK: - USB 디버그 탐지 설정

    /// USB 디버그 탐지 활성화 여부 (기본: true)
    public var usbDebugDetectionEnabled: Bool

    /// USB 디버그 탐지 시 수행할 액션 (기본: "WARN")
    public var usbDebugDetectionAction: String

    // MARK: - VPN 탐지 설정

    /// VPN 탐지 활성화 여부 (기본: true)
    public var vpnDetectionEnabled: Bool

    /// VPN 탐지 시 수행할 액션 (기본: "WARN")
    public var vpnDetectionAction: String

    // MARK: - 화면 캡처 차단 설정

    /// 화면 캡처 차단 활성화 여부 (기본: true)
    public var screenCaptureBlockEnabled: Bool

    /// 화면 캡처 차단 시 수행할 액션 (기본: "WARN")
    public var screenCaptureBlockAction: String

    // MARK: - 해시 검증

    /// 예상되는 앱 바이너리 해시 (nil이면 검증하지 않음)
    public var expectedBinaryHash: String?

    /// 예상되는 코드 서명 해시 (nil이면 검증하지 않음)
    public var expectedSignatureHash: String?

    // MARK: - 기타

    /// 탐지 주기 (초, nil이면 클라이언트 설정 사용)
    public var detectionInterval: TimeInterval?

    /// 정책 최종 업데이트 시각 (ISO 8601 문자열)
    public var updatedAt: String

    // MARK: - 기본값이 포함된 이니셜라이저

    /// 기본값으로 SecurityPolicy를 생성한다.
    public init(
        policyId: String,
        jailbreakDetectionEnabled: Bool = true,
        jailbreakDetectionAction: String = "WARN",
        simulatorDetectionEnabled: Bool = true,
        simulatorDetectionAction: String = "WARN",
        debuggerDetectionEnabled: Bool = true,
        debuggerDetectionAction: String = "WARN",
        integrityCheckEnabled: Bool = true,
        integrityCheckAction: String = "WARN",
        hookingDetectionEnabled: Bool = true,
        hookingDetectionAction: String = "WARN",
        signatureVerifyEnabled: Bool = true,
        signatureVerifyAction: String = "WARN",
        usbDebugDetectionEnabled: Bool = true,
        usbDebugDetectionAction: String = "WARN",
        vpnDetectionEnabled: Bool = true,
        vpnDetectionAction: String = "WARN",
        screenCaptureBlockEnabled: Bool = true,
        screenCaptureBlockAction: String = "WARN",
        expectedBinaryHash: String? = nil,
        expectedSignatureHash: String? = nil,
        detectionInterval: TimeInterval? = nil,
        updatedAt: String = ""
    ) {
        self.policyId = policyId
        self.jailbreakDetectionEnabled = jailbreakDetectionEnabled
        self.jailbreakDetectionAction = jailbreakDetectionAction
        self.simulatorDetectionEnabled = simulatorDetectionEnabled
        self.simulatorDetectionAction = simulatorDetectionAction
        self.debuggerDetectionEnabled = debuggerDetectionEnabled
        self.debuggerDetectionAction = debuggerDetectionAction
        self.integrityCheckEnabled = integrityCheckEnabled
        self.integrityCheckAction = integrityCheckAction
        self.hookingDetectionEnabled = hookingDetectionEnabled
        self.hookingDetectionAction = hookingDetectionAction
        self.signatureVerifyEnabled = signatureVerifyEnabled
        self.signatureVerifyAction = signatureVerifyAction
        self.usbDebugDetectionEnabled = usbDebugDetectionEnabled
        self.usbDebugDetectionAction = usbDebugDetectionAction
        self.vpnDetectionEnabled = vpnDetectionEnabled
        self.vpnDetectionAction = vpnDetectionAction
        self.screenCaptureBlockEnabled = screenCaptureBlockEnabled
        self.screenCaptureBlockAction = screenCaptureBlockAction
        self.expectedBinaryHash = expectedBinaryHash
        self.expectedSignatureHash = expectedSignatureHash
        self.detectionInterval = detectionInterval
        self.updatedAt = updatedAt
    }
}

// MARK: - 정책 캐시 관리

/// 보안 정책을 로컬에 캐싱하는 클래스.
///
/// UserDefaults에 JSON 형태로 저장하며,
/// TTL 기반으로 캐시 만료를 관리한다.
public class PolicyCache {

    // MARK: - 상수

    /// UserDefaults 저장 키 (정책 데이터)
    private static let policyCacheKey = "com.guard.sdk.policy.cache"

    /// UserDefaults 저장 키 (캐시 만료 시각)
    private static let policyExpiresAtKey = "com.guard.sdk.policy.expires_at"

    /// 기본 캐시 TTL (6시간)
    public static let defaultTTL: TimeInterval = 6 * 60 * 60

    /// UserDefaults 인스턴스 (테스트 시 주입 가능)
    private let userDefaults: UserDefaults

    // MARK: - 초기화

    /// PolicyCache를 초기화한다.
    ///
    /// - Parameter userDefaults: 사용할 UserDefaults 인스턴스 (기본: .standard)
    public init(userDefaults: UserDefaults = .standard) {
        self.userDefaults = userDefaults
    }

    // MARK: - 공개 메서드

    /// 보안 정책을 로컬에 저장한다.
    ///
    /// JSON으로 직렬화하여 UserDefaults에 저장하고,
    /// TTL 기반 만료 시각도 함께 저장한다.
    ///
    /// - Parameters:
    ///   - policy: 저장할 보안 정책
    ///   - ttl: 캐시 유효 기간 (초, 기본: 6시간)
    /// - Returns: 저장 성공 여부
    @discardableResult
    public func save(_ policy: SecurityPolicy, ttl: TimeInterval = PolicyCache.defaultTTL) -> Bool {
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = .prettyPrinted
            let data = try encoder.encode(policy)

            userDefaults.set(data, forKey: PolicyCache.policyCacheKey)

            // 만료 시각 저장
            let expiresAt = Date().addingTimeInterval(ttl)
            userDefaults.set(expiresAt.timeIntervalSince1970, forKey: PolicyCache.policyExpiresAtKey)

            userDefaults.synchronize()
            return true
        } catch {
            return false
        }
    }

    /// 캐시된 보안 정책을 로드한다.
    ///
    /// 캐시가 만료되었거나 없는 경우 nil을 반환한다.
    ///
    /// - Returns: 캐시된 보안 정책, 또는 nil
    public func load() -> SecurityPolicy? {
        // 만료 확인
        guard !isCacheExpired() else {
            clear()
            return nil
        }

        guard let data = userDefaults.data(forKey: PolicyCache.policyCacheKey) else {
            return nil
        }

        do {
            let decoder = JSONDecoder()
            let policy = try decoder.decode(SecurityPolicy.self, from: data)
            return policy
        } catch {
            // 역직렬화 실패 시 캐시 정리
            clear()
            return nil
        }
    }

    /// 캐시된 보안 정책을 삭제한다.
    public func clear() {
        userDefaults.removeObject(forKey: PolicyCache.policyCacheKey)
        userDefaults.removeObject(forKey: PolicyCache.policyExpiresAtKey)
        userDefaults.synchronize()
    }

    /// 캐시가 만료되었는지 확인한다.
    ///
    /// - Returns: 만료 여부 (만료 시각 정보가 없으면 만료된 것으로 처리)
    public func isCacheExpired() -> Bool {
        let expiresAtTimestamp = userDefaults.double(forKey: PolicyCache.policyExpiresAtKey)

        // 저장된 만료 시각이 없으면 (0.0) 만료된 것으로 처리
        guard expiresAtTimestamp > 0 else {
            return true
        }

        let expiresAt = Date(timeIntervalSince1970: expiresAtTimestamp)
        return Date() >= expiresAt
    }
}
