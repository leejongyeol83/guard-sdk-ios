// Detector.swift
// Anti-Mobile Service iOS SDK - 탐지기 프로토콜
//
// [CL-09] 모든 보안 탐지 모듈이 채택해야 하는 기본 프로토콜.
// 프로토콜 지향 설계를 통해 DI 및 테스트 용이성을 확보한다.

import Foundation

// MARK: - 탐지기 프로토콜

/// 보안 위협을 탐지하는 모듈의 기본 프로토콜.
///
/// 각 탐지기는 이 프로토콜을 채택하여 특정 보안 위협에 대한
/// 탐지 로직을 구현한다. AnyObject를 채택하여 참조 타입만 허용한다.
///
/// 구현 예시:
/// ```swift
/// final class JailbreakDetector: Detector {
///     let type: DetectionType = .jailbreak
///
///     func detect() -> DetectionResult {
///         // 탈옥 탐지 로직
///         return DetectionResult(type: .jailbreak, detected: false, confidence: 0.0)
///     }
///
///     func isAvailable() -> Bool { true }
/// }
/// ```
///
/// 설계 원칙:
/// - 단일 책임: 하나의 탐지기는 하나의 보안 위협만 담당
/// - 방어적 프로그래밍: detect()에서 예외 발생 시 안전한 기본값 반환
/// - 플랫폼 독립: isAvailable()로 실행 환경에 따른 사용 가능 여부 판단
public protocol Detector: AnyObject {

    /// 이 탐지기가 담당하는 탐지 유형.
    ///
    /// 탐지기 등록, 정책 매칭, 결과 분류에 사용된다.
    /// 탐지기 생성 후 변경되지 않는 상수여야 한다.
    var type: DetectionType { get }

    /// 보안 위협 탐지를 실행하고 결과를 반환한다.
    ///
    /// Swift 레이어와 C 네이티브 레이어의 검사를 조합하여
    /// 종합적인 탐지 결과를 생성한다.
    ///
    /// 구현 시 주의사항:
    /// - C 네이티브 함수 호출 시 반환값 검증 필수 (-1은 오류)
    /// - 예외 발생 시 detected=false, confidence=0.0으로 안전하게 반환
    /// - details에 개별 검사 항목의 결과를 기록
    ///
    /// - Returns: 탐지 결과 (탐지 여부, 신뢰도, 상세 정보 포함)
    func detect() -> DetectionResult

    /// 현재 환경에서 이 탐지기를 사용할 수 있는지 확인한다.
    ///
    /// 예를 들어:
    /// - 시뮬레이터에서는 특정 하드웨어 기반 검사가 불가능
    /// - 특정 iOS 버전에서만 사용 가능한 API가 있는 경우
    /// - C 네이티브 라이브러리 로드 실패 시
    ///
    /// PolicyEngine은 이 메서드가 false를 반환하는 탐지기를 건너뛴다.
    ///
    /// - Returns: 사용 가능 여부
    func isAvailable() -> Bool
}
