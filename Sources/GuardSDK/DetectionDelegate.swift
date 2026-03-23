// DetectionDelegate.swift
// Guard SDK - 탐지 콜백 프로토콜
//
// 호스트 앱에서 보안 탐지 결과를 수신하기 위한 delegate 프로토콜.
// SDK의 비동기 탐지 결과와 오류를 호스트 앱에 전달한다.

import Foundation

// MARK: - 탐지 결과 콜백 프로토콜

/// 보안 탐지 결과를 호스트 앱에 전달하는 delegate 프로토콜.
///
/// 호스트 앱에서 이 프로토콜을 채택하여 탐지 결과에 따른 UI 처리,
/// 앱 종료, 경고 표시 등의 동작을 구현한다.
///
/// 사용 예시:
/// ```swift
/// class AppDelegate: UIResponder, DetectionDelegate {
///     func guardSDK(_ sdk: GuardSDK, didDetect result: DetectionResult) {
///         if result.action == .block {
///             // 앱 종료 또는 기능 차단 처리
///         }
///     }
/// }
/// ```
public protocol DetectionDelegate: AnyObject {

    /// 보안 위협이 탐지되었을 때 호출된다 (단일 결과).
    ///
    /// 탐지된 각 항목마다 개별적으로 호출되므로,
    /// 호스트 앱에서 탐지 유형별로 다른 처리를 할 수 있다.
    ///
    /// - Parameters:
    ///   - sdk: GuardSDK 싱글톤 인스턴스
    ///   - result: 탐지 결과 (유형, 탐지 여부, 신뢰도, 상세 정보)
    func guardSDK(_ sdk: GuardSDK, didDetect result: DetectionResult)

    /// 탐지 사이클이 완료되었을 때 전체 결과와 정책 액션을 전달한다 (배치).
    ///
    /// 모든 탐지기가 실행된 후 한 번 호출되며,
    /// 전체 결과를 종합한 최고 우선순위 액션이 함께 전달된다.
    /// 기본 구현이 제공되므로 선택적으로 구현할 수 있다.
    ///
    /// - Parameters:
    ///   - sdk: GuardSDK 싱글톤 인스턴스
    ///   - results: 전체 탐지 결과 배열
    ///   - action: 정책 기반으로 결정된 최고 우선순위 액션
    func guardSDK(_ sdk: GuardSDK, didCompleteBatch results: [DetectionResult], action: DetectAction)

    /// SDK 내부 오류가 발생했을 때 호출된다.
    ///
    /// 초기화 실패, 네트워크 오류, 세션 만료 등의 오류를 전달한다.
    /// 호스트 앱에서 오류에 따른 적절한 처리를 구현해야 한다.
    ///
    /// - Parameters:
    ///   - sdk: GuardSDK 싱글톤 인스턴스
    ///   - error: 발생한 SDK 오류
    func guardSDK(_ sdk: GuardSDK, didEncounterError error: SdkError)

    /// SDK 상태가 변경되었을 때 호출된다.
    ///
    /// 서버 정책 수신 성공/실패, 세션 토큰 발급 등 주요 이벤트를 알린다.
    ///
    /// - Parameters:
    ///   - sdk: GuardSDK 싱글톤 인스턴스
    ///   - message: 상태 메시지
    func guardSDK(_ sdk: GuardSDK, didUpdateStatus message: String)
}

// MARK: - 기본 구현 (선택적 메서드)

/// 선택적으로 구현할 수 있는 메서드에 기본 구현을 제공한다.
/// didCompleteBatch는 선택적이므로 구현하지 않아도 된다.
public extension DetectionDelegate {

    /// 배치 결과 콜백의 기본 구현 (빈 구현).
    func guardSDK(_ sdk: GuardSDK, didCompleteBatch results: [DetectionResult], action: DetectAction) {
        // 기본 구현: 아무 동작 없음
    }

    /// 상태 업데이트 콜백의 기본 구현 (빈 구현).
    func guardSDK(_ sdk: GuardSDK, didUpdateStatus message: String) {
        // 기본 구현: 아무 동작 없음
    }
}

// MARK: - SDK 오류 타입

/// SDK 내부에서 발생할 수 있는 오류를 정의한다.
///
/// 각 오류 케이스는 발생 상황에 대한 추가 정보를 포함할 수 있다.
public enum SdkError: Error {

    /// SDK 초기화에 실패한 경우 (설정 오류, 서버 응답 실패 등)
    case initializationFailed(String)

    /// 네트워크 통신 오류 (서버 연결 실패, 타임아웃 등)
    case networkError(Error)

    /// 세션 토큰이 만료된 경우 (재인증 필요)
    case sessionExpired

    /// 보안 정책 로드에 실패한 경우 (서버 + 캐시 모두 실패)
    case policyLoadFailed(String)

    /// 특정 탐지 모듈에서 오류가 발생한 경우
    case detectionFailed(DetectionType, String)

    /// API 키가 유효하지 않은 경우 (서버에서 거부)
    case invalidApiKey

    /// 서버 오류 응답 (HTTP 상태 코드 + 메시지)
    case serverError(Int, String)

    /// Keychain 접근 오류 (저장/조회/삭제 실패)
    case keychainError(String)

    /// 분류되지 않은 기타 오류
    case unknown(String)
}

// MARK: - SdkError 설명

extension SdkError: LocalizedError {

    /// 오류에 대한 사용자 친화적 설명을 반환한다.
    public var errorDescription: String? {
        switch self {
        case .initializationFailed(let message):
            return "SDK 초기화 실패: \(message)"
        case .networkError(let error):
            return "네트워크 오류: \(error.localizedDescription)"
        case .sessionExpired:
            return "세션이 만료되었습니다. 재초기화가 필요합니다."
        case .policyLoadFailed(let message):
            return "보안 정책 로드 실패: \(message)"
        case .detectionFailed(let type, let message):
            return "\(type.rawValue) 탐지 실패: \(message)"
        case .invalidApiKey:
            return "유효하지 않은 API 키입니다."
        case .serverError(let code, let message):
            return "서버 오류 (\(code)): \(message)"
        case .keychainError(let message):
            return "Keychain 오류: \(message)"
        case .unknown(let message):
            return "알 수 없는 오류: \(message)"
        }
    }
}
