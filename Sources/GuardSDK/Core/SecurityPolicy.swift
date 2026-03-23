// SecurityPolicy.swift
// Guard SDK - 보안 정책 모델
//
// 서버에서 전달되는 보안 정책 구조체.
// 각 탐지 유형별로 활성화 여부와 탐지 시 수행할 액션을 정의한다.

import Foundation

/// 서버에서 전달되는 보안 정책 구조체.
///
/// 각 탐지 유형별로 활성화 여부와 탐지 시 수행할 액션을 정의한다.
/// Codable을 채택하여 JSON 직렬화/역직렬화를 지원한다.
public struct SecurityPolicy: Codable, Equatable {

    /// 정책 식별자 (서버에서 부여)
    public let policyId: String

    // MARK: - 탈옥 탐지 설정

    /// 탈옥 탐지 활성화 여부 (기본: false)
    public var jailbreakDetectionEnabled: Bool

    /// 탈옥 탐지 시 수행할 액션 (기본: "LOG")
    public var jailbreakDetectionAction: String

    // MARK: - 시뮬레이터 탐지 설정

    /// 시뮬레이터 탐지 활성화 여부 (기본: false)
    public var simulatorDetectionEnabled: Bool

    /// 시뮬레이터 탐지 시 수행할 액션 (기본: "LOG")
    public var simulatorDetectionAction: String

    // MARK: - 디버거 탐지 설정

    /// 디버거 탐지 활성화 여부 (기본: false)
    public var debuggerDetectionEnabled: Bool

    /// 디버거 탐지 시 수행할 액션 (기본: "LOG")
    public var debuggerDetectionAction: String

    // MARK: - 무결성 검증 설정

    /// 앱 무결성 검증 활성화 여부 (기본: false)
    public var integrityCheckEnabled: Bool

    /// 무결성 검증 실패 시 수행할 액션 (기본: "LOG")
    public var integrityCheckAction: String

    // MARK: - 후킹 탐지 설정

    /// 후킹 프레임워크 탐지 활성화 여부 (기본: false)
    public var hookingDetectionEnabled: Bool

    /// 후킹 탐지 시 수행할 액션 (기본: "LOG")
    public var hookingDetectionAction: String

    // MARK: - 서명 검증 설정

    /// 코드 서명 검증 활성화 여부 (기본: false)
    public var signatureVerifyEnabled: Bool

    /// 서명 검증 실패 시 수행할 액션 (기본: "LOG")
    public var signatureVerifyAction: String

    // MARK: - USB 디버그 탐지 설정

    /// USB 디버그 탐지 활성화 여부 (기본: false)
    public var usbDebugDetectionEnabled: Bool

    /// USB 디버그 탐지 시 수행할 액션 (기본: "LOG")
    public var usbDebugDetectionAction: String

    // MARK: - VPN 탐지 설정

    /// VPN 탐지 활성화 여부 (기본: false)
    public var vpnDetectionEnabled: Bool

    /// VPN 탐지 시 수행할 액션 (기본: "LOG")
    public var vpnDetectionAction: String

    // MARK: - 화면 캡처 차단 설정

    /// 화면 캡처 차단 활성화 여부 (기본: false)
    public var screenCaptureBlockEnabled: Bool

    /// 화면 캡처 차단 시 수행할 액션 (기본: "LOG")
    public var screenCaptureBlockAction: String

    // MARK: - 해시 검증

    /// 예상되는 앱 바이너리 해시 (nil이면 검증하지 않음)
    public var expectedBinaryHash: String?

    /// 예상되는 코드 서명 해시 (nil이면 검증하지 않음)
    public var expectedSignatureHash: String?

    // MARK: - 동적 시그니처

    /// 동적 탐지 시그니처 (카테고리별 그룹핑, 글로벌+앱별 통합)
    public var detectionSignatures: [String: [String: [String]]]

    // MARK: - 기타

    /// 탐지 주기 (초, nil이면 클라이언트 설정 사용)
    public var detectionInterval: TimeInterval?

    /// 정책 최종 업데이트 시각 (ISO 8601 문자열)
    public var updatedAt: String

    // MARK: - 기본값이 포함된 이니셜라이저

    /// 기본값으로 SecurityPolicy를 생성한다.
    public init(
        policyId: String,
        jailbreakDetectionEnabled: Bool = false,
        jailbreakDetectionAction: String = "LOG",
        simulatorDetectionEnabled: Bool = false,
        simulatorDetectionAction: String = "LOG",
        debuggerDetectionEnabled: Bool = false,
        debuggerDetectionAction: String = "LOG",
        integrityCheckEnabled: Bool = false,
        integrityCheckAction: String = "LOG",
        hookingDetectionEnabled: Bool = false,
        hookingDetectionAction: String = "LOG",
        signatureVerifyEnabled: Bool = false,
        signatureVerifyAction: String = "LOG",
        usbDebugDetectionEnabled: Bool = false,
        usbDebugDetectionAction: String = "LOG",
        vpnDetectionEnabled: Bool = false,
        vpnDetectionAction: String = "LOG",
        screenCaptureBlockEnabled: Bool = false,
        screenCaptureBlockAction: String = "LOG",
        expectedBinaryHash: String? = nil,
        expectedSignatureHash: String? = nil,
        detectionSignatures: [String: [String: [String]]] = [:],
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
        self.detectionSignatures = detectionSignatures
        self.detectionInterval = detectionInterval
        self.updatedAt = updatedAt
    }
}
