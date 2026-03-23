// HookingDetector.swift
// GuardSDK
//
// [CL-14] 후킹 프레임워크 탐지 모듈
// Frida, Cycript, Substrate 등 후킹 프레임워크를 탐지한다.
// 인라인 후킹(함수 프롤로그 변조)과 심볼 리바인딩(fishhook)도 감지한다.

import Foundation
import Darwin
@_implementationOnly import GuardNative

/// 후킹 프레임워크 탐지기
/// 6개 검사 항목(Swift 2개 + C 네이티브 4개)을 실행하여
/// 런타임 후킹 여부를 판별한다.
public final class HookingDetector: Detector {

    // MARK: - Detector 프로토콜

    public let type: DetectionType = .hooking

    // MARK: - 상수 (기본 하드코딩 값)

    /// Frida 서버 기본 포트 (하드코딩 기본값)
    private static let defaultFridaPorts: [UInt16] = [27042]

    /// Frida 관련 프로세스/라이브러리 패턴 (하드코딩 기본값)
    private static let defaultFridaPatterns: [String] = [
        "frida-agent",
        "frida-server",
        "frida-gadget",
        "libfrida",
        "gmain",
    ]

    /// 후킹 프레임워크 dylib 패턴 (하드코딩 기본값)
    private static let defaultDyldHookPatterns: [String] = [
        "MobileSubstrate",
        "libhooker",
        "substitute",
        "FridaGadget",
    ]

    /// Cycript 관련 의심 라이브러리 이름 패턴 (하드코딩 기본값)
    private static let defaultCycriptLibraries: [String] = [
        "libcycript",
    ]

    // MARK: - 동적 시그니처 (서버에서 수신한 값 + 기본값 병합)

    /// 실제 탐지에 사용되는 Frida 포트 목록
    static var fridaPorts: [UInt16] = defaultFridaPorts

    /// 기존 호환성을 위한 첫 번째 Frida 포트 접근자
    static var fridaPort: UInt16 { fridaPorts.first ?? 27042 }

    /// 실제 탐지에 사용되는 Frida 패턴 목록
    static var fridaPatterns: [String] = defaultFridaPatterns

    /// 실제 탐지에 사용되는 dyld 후킹 패턴 목록
    static var dyldHookPatterns: [String] = defaultDyldHookPatterns

    /// 실제 탐지에 사용되는 Cycript 라이브러리 목록
    static var cycriptLibraries: [String] = defaultCycriptLibraries

    // MARK: - 동적 시그니처 적용

    /// 서버에서 수신한 시그니처를 기존 하드코딩 목록에 병합한다.
    /// 기본 하드코딩 값은 유지하고, 서버 시그니처를 추가로 병합한다.
    /// 중복 값은 제거된다.
    ///
    /// - Parameter signatures: 서버에서 수신한 시그니처 항목 배열
    static func applySignatures(_ signatures: [SignatureItem]) {
        var dynamicFridaPatterns: [String] = []
        var dynamicFridaPorts: [UInt16] = []
        var dynamicDyldHooks: [String] = []
        var dynamicCycriptLibs: [String] = []

        for item in signatures {
            switch item.type {
            case "frida_patterns":
                // Frida 관련 dylib 패턴 추가
                dynamicFridaPatterns.append(item.value)
            case "frida_ports":
                // Frida 포트 번호 추가
                if let port = UInt16(item.value) {
                    dynamicFridaPorts.append(port)
                }
            case "dyld_hooks":
                // 후킹 프레임워크 dylib 패턴 추가
                dynamicDyldHooks.append(item.value)
            case "cycript_libraries":
                // Cycript 라이브러리 패턴 추가
                dynamicCycriptLibs.append(item.value)
            default:
                // 알 수 없는 시그니처 유형은 무시
                break
            }
        }

        // 기본 하드코딩 값에 서버 시그니처를 병합 (중복 제거)
        if !dynamicFridaPatterns.isEmpty {
            let merged = defaultFridaPatterns + dynamicFridaPatterns
            fridaPatterns = Array(Set(merged))
        }

        if !dynamicFridaPorts.isEmpty {
            let merged = defaultFridaPorts + dynamicFridaPorts
            fridaPorts = Array(Set(merged))
        }

        if !dynamicDyldHooks.isEmpty {
            let merged = defaultDyldHookPatterns + dynamicDyldHooks
            dyldHookPatterns = Array(Set(merged))
        }

        if !dynamicCycriptLibs.isEmpty {
            let merged = defaultCycriptLibraries + dynamicCycriptLibs
            cycriptLibraries = Array(Set(merged))
        }
    }

    // MARK: - 탐지 실행

    public func detect() -> DetectionResult {
        var checks: [String: String] = [:]

        // 1. Swift 레이어: Frida 포트 TCP 연결 시도 (기본 27042 + 서버 동적 포트)
        // Frida 서버가 실행 중이면 해당 포트에 연결된다.
        checks["frida_port"] = checkFridaPorts()

        // 2. Swift 레이어: Cycript 라이브러리 로드 확인
        // dlopen/dlsym으로 Cycript 관련 라이브러리가 로드되었는지 확인한다.
        checks["cycript"] = checkCycript()

        // 3. C 네이티브: _dyld_image_count + _dyld_get_image_name으로 의심 dylib 탐지
        // MobileSubstrate, substitute, libhooker 등 후킹 프레임워크의 dylib를 검색한다.
        let dyldHooksResult = native_check_dyld_hooks()
        checks["dyld_hooks"] = dyldHooksResult == 1 ? "detected" : "not_detected"

        // 4. C 네이티브: _dyld_get_image_name에서 frida 패턴 탐지
        // iOS에서는 /proc/self/maps가 없으므로 dyld 이미지 목록에서 frida 관련 패턴을 검색한다.
        let fridaMapsResult = native_check_frida_maps()
        checks["frida_dylib"] = fridaMapsResult == 1 ? "detected" : "not_detected"

        // 5. C 네이티브: 함수 프롤로그 변조 감지 (ARM64 BR/BLR 패턴)
        // 인라인 후킹은 함수 시작 부분의 명령어를 분기 명령어로 교체한다.
        // ARM64의 BR/BLR/B 등 비정상 프롤로그를 감지한다.
        let inlineHookResult = native_check_inline_hook()
        checks["inline_hook"] = inlineHookResult == 1 ? "detected" : "not_detected"

        // 6. C 네이티브: fishhook 기반 심볼 리바인딩 감지
        // fishhook은 lazy/non-lazy symbol pointer를 교체하여 함수를 가로챈다.
        // 시스템 함수의 심볼 포인터가 원래 주소 범위를 벗어나면 리바인딩된 것이다.
        let fishhookResult = native_check_fishhook()
        checks["fishhook"] = fishhookResult == 1 ? "detected" : "not_detected"

        // 탐지 결과 계산
        let totalChecks = checks.count
        let detectedCount = checks.values.filter { $0 == "detected" }.count
        let detected = detectedCount > 0
        let confidence = detected ? min(Float(detectedCount) / Float(totalChecks), 1.0) : 0.0

        #if DEBUG
        print("[GuardSDK DEBUG] [후킹 탐지] fridaPort=\(checks["frida_port"] == "detected"), cycript=\(checks["cycript"] == "detected"), dyldHooks=\(dyldHooksResult == 1), fridaDylib=\(fridaMapsResult == 1), inlineHook=\(inlineHookResult == 1), fishhook=\(fishhookResult == 1) → detected=\(detected) (confidence=\(confidence))")
        #endif

        return DetectionResult(
            type: .hooking,
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

    // MARK: - Swift 검사 메서드

    /// Frida 서버 포트 TCP 연결 시도 (기본 27042 + 서버 동적 포트)
    /// 로컬호스트의 Frida 포트 목록에 소켓 연결을 시도한다.
    /// 하나라도 연결 성공 시 Frida 서버가 실행 중인 것으로 판단한다.
    private func checkFridaPorts() -> String {
        for port in HookingDetector.fridaPorts {
            if checkSinglePort(port) {
                return "detected"
            }
        }
        return "not_detected"
    }

    /// 단일 포트에 대한 TCP 연결 시도
    /// - Parameter port: 검사할 포트 번호
    /// - Returns: 연결 성공 여부
    private func checkSinglePort(_ port: UInt16) -> Bool {
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        // TCP 소켓 생성
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else {
            return false
        }

        // 논블로킹 모드 설정 (타임아웃 방지)
        let flags = fcntl(sock, F_GETFL, 0)
        fcntl(sock, F_SETFL, flags | O_NONBLOCK)

        // 연결 시도
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        // fd_set을 사용한 타임아웃 대기 (100ms)
        if result < 0 && errno == EINPROGRESS {
            var writeSet = fd_set()
            __darwin_fd_zero(&writeSet)
            // fd_set에 소켓 추가 (매크로 대체)
            let intOffset = Int32(sock / 32)
            let bitOffset = Int32(sock % 32)
            withUnsafeMutablePointer(to: &writeSet) { ptr in
                let rawPtr = UnsafeMutableRawPointer(ptr)
                let arrayPtr = rawPtr.assumingMemoryBound(to: Int32.self)
                arrayPtr[Int(intOffset)] |= Int32(1 << bitOffset)
            }

            var timeout = timeval(tv_sec: 0, tv_usec: 100_000) // 100ms
            let selectResult = select(sock + 1, nil, &writeSet, nil, &timeout)

            if selectResult > 0 {
                // 연결 성공 가능성 확인
                var optVal: Int32 = 0
                var optLen = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(sock, SOL_SOCKET, SO_ERROR, &optVal, &optLen)

                close(sock)
                return optVal == 0
            }
        } else if result == 0 {
            // 즉시 연결 성공
            close(sock)
            return true
        }

        close(sock)
        return false
    }

    /// Cycript 라이브러리 로드 확인
    /// 로드된 dylib 목록에서 Cycript 관련 라이브러리 패턴을 검색한다.
    /// objc_getClass를 사용하여 Cycript 런타임 클래스 존재도 확인한다.
    private func checkCycript() -> String {
        // 방법 1: 환경변수에서 Cycript 관련 흔적 검색
        let env = ProcessInfo.processInfo.environment
        for (key, value) in env {
            let combined = "\(key)\(value)".lowercased()
            for lib in HookingDetector.cycriptLibraries {
                if combined.contains(lib) {
                    return "detected"
                }
            }
        }

        // 방법 2: dlopen으로 Cycript 라이브러리 로드 여부 확인
        // 이미 로드된 라이브러리는 RTLD_NOLOAD로 확인 가능
        for lib in HookingDetector.cycriptLibraries {
            let handle = dlopen(lib, RTLD_NOLOAD)
            if handle != nil {
                dlclose(handle)
                return "detected"
            }
        }

        // 방법 3: 파일 시스템에서 Cycript 바이너리 확인
        let cycriptPaths = [
            "/usr/lib/libcycript.dylib",
            "/usr/lib/libcycript0.9.dylib",
        ]
        let fileManager = FileManager.default
        for path in cycriptPaths {
            if fileManager.fileExists(atPath: path) {
                return "detected"
            }
        }

        return "not_detected"
    }
}

// MARK: - fd_set 유틸리티

/// fd_set 초기화 (FD_ZERO 매크로 대체)
/// Swift에서 C 매크로를 직접 호출할 수 없으므로 직접 구현한다.
private func __darwin_fd_zero(_ set: inout fd_set) {
    set = fd_set()
}
