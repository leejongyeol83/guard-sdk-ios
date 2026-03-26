// PolicyEngine.swift
// Guard SDK - 정책 기반 탐지 실행 엔진
//
// 등록된 탐지기(Detector)들을 보안 정책에 따라 실행하고,
// 탐지 결과에 정책 액션을 매핑하여 반환한다.
// 프로토콜 기반 DI로 테스트 용이성을 확보한다.

import Foundation

/// 보안 정책 기반으로 탐지기를 관리하고 실행하는 엔진.
///
/// 생성자 주입 또는 registerDetector를 통해 탐지기를 등록하고,
/// applyPolicy로 서버 정책을 적용한 뒤,
/// runDetection으로 활성화된 탐지기를 실행한다.
public class PolicyEngine {

    // MARK: - 프로퍼티

    /// 등록된 탐지기 목록
    private var detectors: [any Detector]

    /// 현재 적용된 보안 정책
    public private(set) var currentPolicy: SecurityPolicy?

    /// 탐지 유형별 액션 매핑 (정책에서 파생)
    private(set) var actionMap: [DetectionType: DetectAction]

    /// 등록된 탐지기 수
    public var detectorCount: Int {
        return detectors.count
    }

    // MARK: - 초기화

    /// PolicyEngine을 초기화한다.
    ///
    /// - Parameter detectors: 초기 등록할 탐지기 목록 (기본: 빈 배열)
    public init(detectors: [any Detector] = []) {
        self.detectors = detectors
        self.actionMap = [:]
    }

    // MARK: - 탐지기 관리

    /// 탐지기를 등록한다.
    ///
    /// 동일한 타입의 탐지기가 이미 등록되어 있으면 교체한다.
    ///
    /// - Parameter detector: 등록할 탐지기
    public func registerDetector(_ detector: any Detector) {
        // 동일 타입 탐지기가 있으면 제거 후 추가
        detectors.removeAll { $0.type == detector.type }
        detectors.append(detector)
    }

    // MARK: - 정책 적용

    /// 보안 정책을 적용한다.
    ///
    /// 정책에 정의된 각 탐지 유형의 액션을 actionMap에 매핑한다.
    /// 이후 runDetection() 호출 시 이 정책이 반영된다.
    ///
    /// - Parameter policy: 적용할 보안 정책
    public func applyPolicy(_ policy: SecurityPolicy) {
        self.currentPolicy = policy

        // 정책에서 액션 매핑 구성
        actionMap = [:]
        actionMap[.jailbreak] = parseAction(policy.jailbreakDetectionAction)
        actionMap[.simulator] = parseAction(policy.simulatorDetectionAction)
        actionMap[.debugger] = parseAction(policy.debuggerDetectionAction)
        actionMap[.integrity] = parseAction(policy.integrityCheckAction)
        actionMap[.hooking] = parseAction(policy.hookingDetectionAction)
        actionMap[.signature] = parseAction(policy.signatureVerifyAction)
        actionMap[.usbDebug] = parseAction(policy.usbDebugDetectionAction)
        actionMap[.vpn] = parseAction(policy.vpnDetectionAction)
        actionMap[.screenCapture] = parseAction(policy.screenCaptureBlockAction)

        // 정책 적용 디버그 로그
        for type in DetectionType.allCases {
            let enabled = isDetectionEnabled(for: type, policy: policy)
            let action = actionMap[type] ?? .log
            GuardSDK.shared.log(.debug, "[정책] \(type.rawValue) → enabled=\(enabled), action=\(action)")
        }

        // 무결성 검증용 기대 해시값 전달
        for detector in detectors {
            if let integrityDetector = detector as? IntegrityDetector {
                integrityDetector.expectedBinaryHash = policy.expectedBinaryHash
                integrityDetector.expectedSignatureHash = policy.expectedSignatureHash
            }
            if let sigDetector = detector as? SignatureDetector {
                sigDetector.expectedSignatureHash = policy.expectedSignatureHash
            }
        }
    }

    // MARK: - 탐지 실행

    /// 등록된 모든 활성 탐지기를 실행하고 결과를 반환한다.
    ///
    /// 정책이 적용된 경우, 비활성화된 탐지 유형은 건너뛴다.
    /// 각 결과에는 정책 기반 액션이 포함된다.
    ///
    /// - Returns: 탐지 결과 배열
    public func runDetection() -> [DetectionResult] {
        var results: [DetectionResult] = []

        for detector in detectors {
            // 탐지기 사용 가능 여부 확인
            guard detector.isAvailable() else {
                continue
            }

            // 정책이 있는 경우, 비활성화된 탐지 유형 건너뛰기
            if let policy = currentPolicy {
                guard isDetectionEnabled(for: detector.type, policy: policy) else {
                    continue
                }
            }

            // 탐지 실행
            var result = detector.detect()

            // 정책 기반 액션 적용
            let action = getAction(for: result.type)
            result = DetectionResult(
                type: result.type,
                detected: result.detected,
                confidence: result.confidence,
                details: result.details,
                timestamp: result.timestamp,
                action: action
            )

            results.append(result)
        }

        return results
    }

    /// 특정 탐지 유형에 대한 정책 액션을 반환한다.
    ///
    /// actionMap에 매핑이 없으면 기본값 .log를 반환한다.
    ///
    /// - Parameter type: 탐지 유형
    /// - Returns: 정책 기반 액션
    public func getAction(for type: DetectionType) -> DetectAction {
        return actionMap[type] ?? .log
    }

    // MARK: - 탐지기 접근

    /// 특정 타입의 탐지기를 반환한다.
    /// ScreenCaptureDetector 등 외부에서 직접 제어가 필요한 탐지기 접근용.
    public func getDetector(for type: DetectionType) -> (any Detector)? {
        return detectors.first { $0.type == type }
    }

    // MARK: - 동적 시그니처 적용

    /// 서버에서 수신한 동적 시그니처를 각 탐지기에 적용한다.
    /// category별로 분류하여 해당 탐지기에 전달한다.
    /// - root → JailbreakDetector
    /// - hooking → HookingDetector
    ///
    /// SignatureData는 SignatureItem으로 변환하여 기존 탐지기 인터페이스를 유지한다.
    ///
    /// - Parameter signatures: 서버에서 수신한 시그니처 배열
    public func applySignatures(_ signatures: [String: [String: [String]]]) {
        // { "root": { "path": [...], "package": [...] }, "hooking": { "library": [...], "port": [...] } }
        let rootSignatures = (signatures["root"] ?? [:]).flatMap { (checkMethod, values) in
            values.map { SignatureItem(type: checkMethod, value: $0) }
        }

        let hookingSignatures = (signatures["hooking"] ?? [:]).flatMap { (checkMethod, values) in
            values.map { SignatureItem(type: checkMethod, value: $0) }
        }

        // 탈옥 탐지 시그니처 적용
        if !rootSignatures.isEmpty {
            JailbreakDetector.applySignatures(rootSignatures)
        }

        // 후킹 탐지 시그니처 적용
        if !hookingSignatures.isEmpty {
            HookingDetector.applySignatures(hookingSignatures)
        }
    }

    // MARK: - 비공개 헬퍼

    /// 정책 액션 문자열을 DetectAction enum으로 변환한다.
    ///
    /// - Parameter actionString: 서버 정책의 액션 문자열 (BLOCK, WARN, LOG, NONE)
    /// - Returns: 변환된 DetectAction (알 수 없는 값은 .log)
    private func parseAction(_ actionString: String) -> DetectAction {
        switch actionString.uppercased() {
        case "BLOCK":
            return .block
        case "WARN":
            return .warn
        case "LOG":
            return .log
        case "NONE":
            return .none
        default:
            return .log
        }
    }

    /// 정책에서 해당 탐지 유형이 활성화되어 있는지 확인한다.
    ///
    /// - Parameters:
    ///   - type: 탐지 유형
    ///   - policy: 보안 정책
    /// - Returns: 활성화 여부
    private func isDetectionEnabled(for type: DetectionType, policy: SecurityPolicy) -> Bool {
        switch type {
        case .jailbreak:
            return policy.jailbreakDetectionEnabled
        case .simulator:
            return policy.simulatorDetectionEnabled
        case .debugger:
            return policy.debuggerDetectionEnabled
        case .integrity:
            return policy.integrityCheckEnabled
        case .hooking:
            return policy.hookingDetectionEnabled
        case .signature:
            return policy.signatureVerifyEnabled
        case .usbDebug:
            return policy.usbDebugDetectionEnabled
        case .vpn:
            return policy.vpnDetectionEnabled
        case .screenCapture:
            return policy.screenCaptureBlockEnabled
        }
    }
}
