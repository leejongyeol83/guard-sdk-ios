// GuardCallback.swift
// Guard SDK - 콜백 프로토콜
//
// 호스트 앱에서 SDK 초기화 완료, 보안 탐지 결과, 에러를 수신하기 위한 콜백 프로토콜.
// Android GuardCallback 인터페이스와 동일한 구조.

import Foundation

// MARK: - 정책 출처

/// 현재 적용된 보안 정책의 출처를 나타낸다.
public enum PolicySource: String {
    /// GuardConfig 기본값만 적용
    case config
    /// 캐시된 서버 정책 적용
    case cached
    /// 서버에서 새로 수신한 정책 적용
    case server
}

// MARK: - Guard 콜백 프로토콜

/// SDK 초기화 완료, 보안 탐지 결과, 에러를 수신하는 콜백 프로토콜.
///
/// 호스트 앱에서 이 프로토콜을 채택하여 탐지 결과에 따른 UI 처리,
/// 앱 종료, 경고 표시 등의 동작을 구현한다.
///
/// 사용 예시:
/// ```swift
/// GuardSDK.shared.initialize(config: config, callback: self)
/// GuardSDK.shared.startDetection()
///
/// extension ViewController: GuardCallback {
///     func onReady(policySource: PolicySource) {
///         // 서버 정책 적용 완료 (또는 폴백)
///     }
///     func onDetection(result: DetectionResult) {
///         // 개별 탐지 결과 처리
///     }
/// }
/// ```
public protocol GuardCallback: AnyObject {

    /// 서버 정책 수신이 완료되었을 때 호출된다 (1회만).
    ///
    /// 서버 연결 실패 시에도 캐시/기본 정책으로 폴백하여 호출된다.
    /// 이 시점 이후 SDK가 최종 정책으로 동작 중임을 보장한다.
    ///
    /// - Parameter policySource: 현재 적용된 정책 출처
    func onReady(policySource: PolicySource)

    /// 보안 위협이 탐지되었을 때 호출된다 (단일 결과).
    ///
    /// - Parameter result: 탐지 결과 (유형, 탐지 여부, 신뢰도, 상세 정보)
    func onDetection(result: DetectionResult)

    /// 탐지 사이클이 완료되었을 때 전체 결과와 정책 액션을 전달한다.
    ///
    /// - Parameters:
    ///   - results: 전체 탐지 결과 배열
    ///   - action: 정책 기반으로 결정된 최고 우선순위 액션
    func onDetectionBatch(results: [DetectionResult], action: DetectAction)

    /// SDK 내부 오류가 발생했을 때 호출된다.
    ///
    /// - Parameter error: 발생한 SDK 오류
    func onError(error: SdkError)
}

// MARK: - 기본 구현 (선택적 메서드)

public extension GuardCallback {

    func onReady(policySource: PolicySource) {}

    func onDetectionBatch(results: [DetectionResult], action: DetectAction) {}

    func onError(error: SdkError) {}
}

// MARK: - SDK 오류 타입

/// SDK 내부에서 발생할 수 있는 오류를 정의한다.
public enum SdkError: Error {

    /// SDK 초기화에 실패한 경우
    case initializationFailed(String)

    /// 네트워크 통신 오류
    case networkError(Error)

    /// 세션 토큰이 만료된 경우
    case sessionExpired

    /// 보안 정책 로드에 실패한 경우
    case policyLoadFailed(String)

    /// 특정 탐지 모듈에서 오류가 발생한 경우
    case detectionFailed(DetectionType, String)

    /// API 키가 유효하지 않은 경우
    case invalidApiKey

    /// 서버 오류 응답
    case serverError(Int, String)

    /// Keychain 접근 오류
    case keychainError(String)

    /// 분류되지 않은 기타 오류
    case unknown(String)
}

// MARK: - SdkError 설명

extension SdkError: LocalizedError {

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

// MARK: - 하위 호환

@available(*, deprecated, renamed: "GuardCallback", message: "GuardCallback으로 대체되었습니다.")
public typealias DetectionDelegate = GuardCallback
