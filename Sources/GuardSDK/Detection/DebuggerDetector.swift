// DebuggerDetector.swift
// GuardSDK
//
// [CL-12] 디버거 탐지 모듈
// sysctl, ptrace 기반으로 디버거 연결을 탐지한다.
// 핵심 로직은 C 네이티브 레이어에서 실행된다.

import Foundation
@_implementationOnly import GuardNative

/// 디버거 탐지기
/// 4개 검사 항목(Swift 1개 + C 네이티브 3개)을 실행하여
/// 디버거 연결 여부를 판별한다.
public final class DebuggerDetector: Detector {

    // MARK: - Detector 프로토콜

    public let type: DetectionType = .debugger

    // MARK: - 탐지 실행

    public func detect() -> DetectionResult {
        var checks: [String: String] = [:]

        // 1. Swift 레이어: DYLD_INSERT_LIBRARIES 환경변수 검사
        // 이 환경변수가 설정되어 있으면 외부 라이브러리가 주입된 것이다.
        // 디버거, 프록시, 코드 인젝션 도구가 이 방법을 사용한다.
        if ProcessInfo.processInfo.environment["DYLD_INSERT_LIBRARIES"] != nil {
            checks["dyld_insert"] = "detected"
        } else {
            checks["dyld_insert"] = "not_detected"
        }

        // 2. C 네이티브: sysctl → kinfo_proc.kp_proc.p_flag & P_TRACED
        // P_TRACED 플래그가 설정되어 있으면 프로세스가 디버거에 의해 추적 중이다.
        let sysctlResult = native_check_sysctl()
        checks["sysctl_traced"] = sysctlResult == 1 ? "detected" : "not_detected"

        // 3. C 네이티브: ptrace(PT_DENY_ATTACH) 호출
        // 디버거가 이미 연결된 경우 PT_DENY_ATTACH가 실패한다.
        // 성공 시 이후 디버거 연결을 차단한다.
        let ptraceResult = native_deny_attach()
        checks["ptrace_deny"] = ptraceResult == 1 ? "detected" : "not_detected"

        // 4. C 네이티브: task_get_exception_ports로 디버거 확인
        // 디버거가 연결되면 exception port가 변경된다.
        // 비정상 exception port가 감지되면 디버거가 연결된 것이다.
        let exceptionResult = native_check_exception_ports()
        checks["exception_ports"] = exceptionResult == 1 ? "detected" : "not_detected"

        // 탐지 결과 계산
        let totalChecks = checks.count
        let detectedCount = checks.values.filter { $0 == "detected" }.count
        let detected = detectedCount > 0
        let confidence = detected ? min(Float(detectedCount) / Float(totalChecks), 1.0) : 0.0

        return DetectionResult(
            type: .debugger,
            detected: detected,
            confidence: confidence,
            details: checks,
            timestamp: Date(),
            action: .log
        )
    }

    public func isAvailable() -> Bool {
        return true
    }
}
