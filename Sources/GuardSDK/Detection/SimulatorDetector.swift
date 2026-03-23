// SimulatorDetector.swift
// GuardSDK
//
// [CL-11] 시뮬레이터 탐지 모듈
// Xcode 시뮬레이터 실행 환경을 컴파일 타임 + 런타임 이중 검사로 탐지한다.
// C 네이티브 호출 없이 Swift 레이어만으로 동작한다.

import Foundation

/// 시뮬레이터 탐지기
/// 4개 검사 항목(컴파일 플래그 2개 + 런타임 2개)을 실행하여
/// Xcode 시뮬레이터 환경에서의 실행 여부를 판별한다.
public final class SimulatorDetector: Detector {

    // MARK: - Detector 프로토콜

    public let type: DetectionType = .simulator

    // MARK: - 탐지 실행

    public func detect() -> DetectionResult {
        var checks: [String: String] = [:]

        // 1. 컴파일 타임 검사: #if targetEnvironment(simulator)
        // 시뮬레이터 빌드 시에만 "detected"로 설정된다.
        #if targetEnvironment(simulator)
        checks["compile_flag"] = "detected"
        #else
        checks["compile_flag"] = "not_detected"
        #endif

        // 2. 런타임 검사: SIMULATOR_DEVICE_NAME 환경변수
        // Xcode 시뮬레이터는 이 환경변수를 자동으로 설정한다.
        if ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil {
            checks["env_simulator"] = "detected"
        } else {
            checks["env_simulator"] = "not_detected"
        }

        // 3. 컴파일 타임 검사: x86_64 아키텍처
        // Intel Mac에서 실행되는 시뮬레이터는 x86_64 아키텍처를 사용한다.
        // Apple Silicon Mac에서는 arm64이므로 이 검사만으로는 불충분하다.
        #if arch(x86_64)
        checks["architecture"] = "detected"
        #else
        checks["architecture"] = "not_detected"
        #endif

        // 4. 런타임 검사: utsname().machine 모델명
        // 시뮬레이터에서는 "x86_64" 또는 "i386" 등의 모델명이 반환된다.
        // 실제 기기에서는 "iPhone14,5" 등의 기기 모델명이 반환된다.
        let machineModel = getMachineModel()
        if machineModel.contains("x86") || machineModel.contains("i386") {
            checks["machine_model"] = "detected"
        } else {
            checks["machine_model"] = "not_detected"
        }

        // 탐지 결과 계산
        let totalChecks = checks.count
        let detectedCount = checks.values.filter { $0 == "detected" }.count
        let detected = detectedCount > 0
        let confidence = detected ? min(Float(detectedCount) / Float(totalChecks), 1.0) : 0.0

        #if DEBUG
        print("[GuardSDK DEBUG] [시뮬레이터 탐지] compileFlag=\(checks["compile_flag"] == "detected"), envSimulator=\(checks["env_simulator"] == "detected"), architecture=\(checks["architecture"] == "detected"), machineModel=\(checks["machine_model"] == "detected") → detected=\(detected) (confidence=\(confidence))")
        #endif

        return DetectionResult(
            type: .simulator,
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

    // MARK: - 내부 유틸리티

    /// utsname 구조체에서 machine 필드를 문자열로 추출한다.
    /// 시뮬레이터: "x86_64" 또는 "arm64" (Apple Silicon)
    /// 실기기: "iPhone14,5", "iPad13,4" 등
    private func getMachineModel() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        let machine = withUnsafePointer(to: &systemInfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                String(cString: $0)
            }
        }
        return machine
    }
}
