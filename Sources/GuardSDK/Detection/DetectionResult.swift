// DetectionResult.swift
// Guard SDK - 탐지 결과 모델
//
// [CL-08] 각 탐지기가 반환하는 결과 구조체와,
// 탐지 유형/액션을 정의하는 열거형을 포함한다.

import Foundation

// MARK: - 탐지 유형

/// SDK가 지원하는 보안 위협 탐지 유형.
///
/// 각 유형은 독립적인 Detector 구현체에 의해 검사된다.
public enum DetectionType: String, Codable, CaseIterable {

    /// 탈옥 탐지 - Cydia, Sileo 등 탈옥 흔적 검사
    case jailbreak = "root"

    /// 시뮬레이터 탐지 - Xcode 시뮬레이터 실행 환경 검사
    case simulator = "emulator"

    /// 디버거 탐지 - sysctl, exception ports 기반 디버거 연결 검사
    case debugger

    /// 앱 무결성 검증 - 바이너리 해시, 코드 서명 검증
    case integrity

    /// 후킹 프레임워크 탐지 - Frida, Cycript, Substrate 등 검사
    case hooking

    /// 코드 서명 검증 - 인증서 해시 기반 서명 변조 검사
    case signature

    /// USB 디버그 탐지 - USB 디버깅 모드 활성화 환경 검사
    case usbDebug = "usb_debug"

    /// VPN 탐지 - VPN 연결 상태 검사
    case vpn

    /// 화면 캡처 차단 - 스크린샷/녹화 감지
    case screenCapture = "screen_capture"
}

// MARK: - 탐지 액션

/// 보안 위협이 탐지되었을 때 수행할 액션.
///
/// 서버의 보안 정책에 의해 탐지 유형별로 지정된다.
public enum DetectAction: String, Codable {

    /// 앱 종료 또는 기능 차단 - 가장 강력한 대응
    case block

    /// delegate 호출하여 호스트 앱에서 UI 처리 (경고 팝업 등)
    case warn

    /// 서버에 리포팅만 수행하고 앱 동작에는 영향 없음
    case log

    /// 아무 동작 없음 (모니터링 용도)
    case none
}

// MARK: - 탐지 결과

/// 개별 탐지기의 실행 결과를 나타내는 구조체.
///
/// 탐지 유형, 탐지 여부, 신뢰도, 상세 정보, 정책 액션 등을 포함한다.
/// 불변(immutable) 구조체로, 생성 후 변경할 수 없다.
public struct DetectionResult {

    /// 탐지 유형 (탈옥, 시뮬레이터, 디버거, 무결성, 후킹)
    public let type: DetectionType

    /// 위협이 탐지되었는지 여부
    public let detected: Bool

    /// 탐지 신뢰도 (0.0 ~ 1.0)
    /// 여러 검사 항목 중 탐지된 비율에 비례한다.
    public let confidence: Float

    /// 상세 정보 (탐지 방법, 경로, 개별 검사 결과 등)
    public let details: [String: String]

    /// 탐지 시점
    public let timestamp: Date

    /// 정책 기반 액션 (PolicyEngine에 의해 설정됨)
    public let action: DetectAction

    /// DetectionResult를 생성한다.
    ///
    /// - Parameters:
    ///   - type: 탐지 유형
    ///   - detected: 위협 탐지 여부
    ///   - confidence: 탐지 신뢰도 (0.0 ~ 1.0, 범위 외 값은 클램핑)
    ///   - details: 상세 정보 딕셔너리 (기본: 빈 딕셔너리)
    ///   - timestamp: 탐지 시점 (기본: 현재 시각)
    ///   - action: 정책 기반 액션 (기본: .log)
    public init(
        type: DetectionType,
        detected: Bool,
        confidence: Float,
        details: [String: String] = [:],
        timestamp: Date = Date(),
        action: DetectAction = .log
    ) {
        self.type = type
        self.detected = detected
        // 신뢰도를 0.0 ~ 1.0 범위로 클램핑
        self.confidence = min(max(confidence, 0.0), 1.0)
        self.details = details
        self.timestamp = timestamp
        self.action = action
    }
}

// MARK: - Equatable 적합성

extension DetectionResult: Equatable {
    public static func == (lhs: DetectionResult, rhs: DetectionResult) -> Bool {
        return lhs.type == rhs.type
            && lhs.detected == rhs.detected
            && lhs.confidence == rhs.confidence
            && lhs.details == rhs.details
            && lhs.action == rhs.action
    }
}
