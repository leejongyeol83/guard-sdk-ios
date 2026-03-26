// SimulatorDetector.swift
// GuardSDK
//
// [CL-11] 시뮬레이터 탐지 모듈
// Xcode 시뮬레이터 실행 환경을 컴파일 타임 + 런타임 이중 검사로 탐지한다.
// C 네이티브 호출 없이 Swift 레이어만으로 동작한다.

import Foundation

/// 시뮬레이터 탐지기
/// 7개 검사 항목(컴파일 플래그 2개 + 런타임 5개)을 실행하여
/// Xcode 시뮬레이터 환경에서의 실행 여부를 판별한다.
/// Apple Silicon(arm64) 시뮬레이터도 런타임 체크로 탐지한다.
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
        // Apple Silicon 시뮬레이터에서는 "arm64"가 반환되어 실기기와 구분 불가.
        // 실제 기기에서는 "iPhone14,5", "iPad13,4" 등의 기기 모델명이 반환된다.
        let machineModel = getMachineModel()
        if machineModel.contains("x86") || machineModel.contains("i386") {
            checks["machine_model"] = "detected"
        } else if machineModel == "arm64" {
            // arm64만 반환되면 시뮬레이터 가능성 (실기기는 "iPhone15,2" 등 모델명)
            checks["machine_model"] = "detected"
        } else {
            checks["machine_model"] = "not_detected"
        }

        // 5. 런타임 검사: SIMULATOR_RUNTIME_VERSION 환경변수
        // Xcode 시뮬레이터가 설정하는 추가 환경변수
        if ProcessInfo.processInfo.environment["SIMULATOR_RUNTIME_VERSION"] != nil {
            checks["env_runtime_version"] = "detected"
        } else {
            checks["env_runtime_version"] = "not_detected"
        }

        // 6. 런타임 검사: 시뮬레이터 전용 디렉토리 존재 여부
        // 시뮬레이터 앱 데이터는 CoreSimulator 경로 아래에 위치한다.
        let homeDir = NSHomeDirectory()
        if homeDir.contains("CoreSimulator") || homeDir.contains("Simulator") {
            checks["simulator_path"] = "detected"
        } else {
            checks["simulator_path"] = "not_detected"
        }

        // 7. 런타임 검사: 실기기 전용 하드웨어 특성
        // 실기기에는 항상 카메라 등 센서가 존재하지만, 시뮬레이터에는 없다.
        // ProcessInfo의 thermalState를 활용 — 시뮬레이터는 열 관리가 없다.
        // 대신 더 신뢰할 수 있는 방법: 실기기 모델명 패턴 매칭
        let isRealDeviceModel = machineModel.hasPrefix("iPhone") ||
            machineModel.hasPrefix("iPad") ||
            machineModel.hasPrefix("iPod") ||
            machineModel.hasPrefix("Watch") ||
            machineModel.hasPrefix("AppleTV")
        if !isRealDeviceModel {
            checks["device_model_pattern"] = "detected"
        } else {
            checks["device_model_pattern"] = "not_detected"
        }

        // 탐지 결과 계산
        let totalChecks = checks.count
        let detectedCount = checks.values.filter { $0 == "detected" }.count
        let detected = detectedCount > 0
        let confidence = detected ? min(Float(detectedCount) / Float(totalChecks), 1.0) : 0.0

        #if DEBUG
        let detectedItems = checks.filter { $0.value == "detected" }.map { $0.key }
        print("[GuardSDK DEBUG] [시뮬레이터 탐지] \(detectedItems.count)/\(totalChecks) 항목 탐지: \(detectedItems.joined(separator: ", ")) → detected=\(detected) (confidence=\(confidence))")
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
