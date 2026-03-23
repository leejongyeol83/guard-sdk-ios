// ApiModels.swift
// GuardSDK - Codable 요청/응답 모델
//
// 서버 API 스펙에 맞춘 요청/응답 모델 정의
// snake_case JSON <-> camelCase Swift 자동 변환 (CodingKeys 사용)

import Foundation

// MARK: - SDK 초기화 요청

/// SDK 초기화 요청 모델
/// POST /api/sdk/guard/init 에 전송
/// 인증은 X-API-Key, X-Device-Id 헤더로 처리
struct SdkInitRequest: Codable {
    /// 플랫폼 식별자 (항상 "ios")
    let platform: String
    /// iOS 운영체제 버전 (예: "17.4")
    let osVersion: String
    /// 디바이스 모델명 (예: "iPhone15,2")
    let deviceModel: String
    /// 호스트 앱 버전
    let appVersion: String
    /// SDK 버전 (예: "1.0.0")
    let sdkVersion: String

    enum CodingKeys: String, CodingKey {
        case platform
        case osVersion = "os_version"
        case deviceModel = "device_model"
        case appVersion = "app_version"
        case sdkVersion = "sdk_version"
    }
}

// MARK: - SDK 초기화 응답

/// SDK 초기화 응답 모델 (API 서버 스펙에 맞춤)
struct SdkInitResponse: Codable {
    /// 세션 토큰 (이후 API 호출에 사용)
    let sessionToken: String
    /// 서버에서 내려준 보안 정책
    let policy: PolicyResponse
    /// 서버에서 내려준 동적 시그니처 (선택, 없으면 기본 하드코딩 값 사용)
    let signatures: SdkSignaturesResponse?

    enum CodingKeys: String, CodingKey {
        case sessionToken = "session_token"
        case policy
        case signatures
    }
}

// MARK: - 동적 시그니처 모델

/// 개별 시그니처 항목 모델
/// 서버에서 동적으로 탐지 시그니처를 내려줄 때 사용한다.
public struct SignatureItem: Codable {
    /// 시그니처 유형 (예: "jailbreak_paths", "frida_patterns")
    public let type: String
    /// 시그니처 값 (경로, 패턴, 포트 등)
    public let value: String
}

/// SDK 시그니처 응답 모델
/// 탈옥(root) 및 후킹(hooking) 탐지에 사용할 동적 시그니처 목록을 포함한다.
public struct SdkSignaturesResponse: Codable {
    /// 탈옥 탐지용 시그니처 목록
    public let root: [SignatureItem]
    /// 후킹 탐지용 시그니처 목록
    public let hooking: [SignatureItem]

    /// 기본값 이니셜라이저 (빈 시그니처)
    public init(root: [SignatureItem] = [], hooking: [SignatureItem] = []) {
        self.root = root
        self.hooking = hooking
    }
}

/// 보안 정책 응답 모델 (API 서버 스펙에 맞춤)
struct PolicyResponse: Codable {
    let integrityCheckEnabled: Bool
    let rootDetectionEnabled: Bool
    let emulatorDetectionEnabled: Bool
    let debuggerDetectionEnabled: Bool
    let hookingDetectionEnabled: Bool
    let signatureVerifyEnabled: Bool?
    let usbDebugDetectionEnabled: Bool?
    let vpnDetectionEnabled: Bool?
    let screenCaptureBlockEnabled: Bool?
    let onDetectAction: String
    let checkIntervalSeconds: Int
    let detectionActions: [String: String]?
    let expectedApkHash: String?
    let expectedSignatureHash: String?

    enum CodingKeys: String, CodingKey {
        case integrityCheckEnabled = "integrity_check_enabled"
        case rootDetectionEnabled = "root_detection_enabled"
        case emulatorDetectionEnabled = "emulator_detection_enabled"
        case debuggerDetectionEnabled = "debugger_detection_enabled"
        case hookingDetectionEnabled = "hooking_detection_enabled"
        case signatureVerifyEnabled = "signature_verify_enabled"
        case usbDebugDetectionEnabled = "usb_debug_detection_enabled"
        case vpnDetectionEnabled = "vpn_detection_enabled"
        case screenCaptureBlockEnabled = "screen_capture_block_enabled"
        case onDetectAction = "on_detect_action"
        case checkIntervalSeconds = "check_interval_seconds"
        case detectionActions = "detection_actions"
        case expectedApkHash = "expected_apk_hash"
        case expectedSignatureHash = "expected_signature_hash"
    }
}

// MARK: - 탐지 이벤트

/// DetectionEvent 타입 별칭 (DetectionReporter에서 사용)
typealias DetectionEvent = DetectionEventModel

/// 개별 탐지 이벤트 모델 (API 서버 스펙에 맞춤)
struct DetectionEventModel: Codable {
    /// 탐지 유형 (예: "jailbreak", "debugger")
    let type: String
    /// 심각도 - 서버가 탐지 유형 기준으로 재결정 (기본값 전송)
    let severity: String
    /// ISO 8601 타임스탬프
    let timestamp: String
    /// 메타데이터
    let metadata: [String: String]

    init(type: String, severity: String = "medium", timestamp: String, metadata: [String: String] = [:]) {
        self.type = type
        self.severity = severity
        self.timestamp = timestamp
        self.metadata = metadata
    }

    enum CodingKeys: String, CodingKey {
        case type
        case severity
        case timestamp
        case metadata
    }
}

// MARK: - 탐지 리포트 요청

/// 탐지 결과 리포트 요청 모델 (API 서버 스펙에 맞춤)
/// POST /api/sdk/guard/report 에 전송
/// 인증은 X-Session-Token 헤더로 처리
struct DetectionReportRequest: Codable {
    /// 탐지 이벤트 목록
    let detections: [DetectionEventModel]

    enum CodingKeys: String, CodingKey {
        case detections
    }
}

// MARK: - 탐지 리포트 응답

/// 탐지 결과 리포트 응답 모델 (API 서버 스펙에 맞춤)
struct DetectionReportResponse: Codable {
    /// 수신된 이벤트 건수
    let received: Int
    /// 서버가 결정한 액션
    let action: String

    enum CodingKeys: String, CodingKey {
        case received
        case action
    }
}

// MARK: - 하트비트 요청

/// 하트비트 요청 모델 (빈 바디)
/// POST /api/sdk/guard/heartbeat 에 전송
/// 인증은 X-Session-Token 헤더로 처리
struct HeartbeatRequest: Codable {}

// MARK: - 하트비트 응답

/// 하트비트 응답 모델 (API 서버 스펙에 맞춤)
struct HeartbeatResponse: Decodable {
    /// 상태 ("alive" / "expired")
    let status: String
    /// 세션 유효 여부
    let sessionValid: Bool
    /// 정책 업데이트 여부
    let policyUpdated: Bool
    /// 업데이트된 정책 (policyUpdated가 true일 때만 포함)
    let policy: SecurityPolicy?

    enum CodingKeys: String, CodingKey {
        case status
        case sessionValid = "session_valid"
        case policyUpdated = "policy_updated"
        case policy
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        status = try container.decode(String.self, forKey: .status)
        sessionValid = try container.decodeIfPresent(Bool.self, forKey: .sessionValid) ?? true
        policyUpdated = try container.decodeIfPresent(Bool.self, forKey: .policyUpdated) ?? false
        policy = try container.decodeIfPresent(SecurityPolicy.self, forKey: .policy)
    }
}

// MARK: - 서버 에러 응답

/// 서버 에러 응답 모델 (공통)
struct ApiErrorResponse: Codable {
    /// 에러 코드
    let code: Int
    /// 에러 메시지
    let message: String

    enum CodingKeys: String, CodingKey {
        case code
        case message
    }
}
