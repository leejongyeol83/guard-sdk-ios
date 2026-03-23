// JailbreakDetector.swift
// GuardSDK
//
// [CL-10] 탈옥 탐지 모듈
// 탈옥 여부를 Swift + C 네이티브 조합으로 탐지한다.
// confidence는 탐지된 항목 수 / 전체 검사 항목 수 비율로 계산된다.

import Foundation
@_implementationOnly import GuardNative

/// 탈옥(Jailbreak) 탐지기
/// 6개 검사 항목(Swift 3개 + C 네이티브 3개)을 실행하여 탈옥 여부를 판별한다.
public final class JailbreakDetector: Detector {

    // MARK: - Detector 프로토콜

    public let type: DetectionType = .jailbreak

    // MARK: - 의심 경로 목록 (기본 하드코딩 값)

    /// 탈옥 환경에서 흔히 존재하는 파일/디렉토리 경로 (하드코딩 기본값)
    /// 오탐 방지를 위해 시스템 경로(/usr/bin/ssh 등) 제외
    private static let defaultSuspiciousPaths: [String] = [
        "/Applications/Cydia.app",
        "/Library/MobileSubstrate/MobileSubstrate.dylib",
        "/bin/bash",
        "/usr/sbin/sshd",
        "/etc/apt",
        "/private/var/lib/apt/",
        "/var/lib/cydia",
        "/Applications/Sileo.app",
        "/var/jb",
        "/var/binpack",
        "/Applications/Zebra.app",
        // Dopamine (iOS 15-16.6.1 탈옥) — rootless 방식
        "/var/jb/.installed_dopamine",
        "/var/jb/basebin",
        // palera1n (iOS 15-17 탈옥)
        "/cores/binpack",
        "/cores/jbloader",
        // KernBypass — 탈옥 탐지 우회 트윅 자체 탐지
        "/var/mobile/Library/KernBypass",
        // Trollstore (영구 앱 설치)
        "/var/containers/Bundle/Application/trollstore",
        "/Applications/TrollStore.app",
    ]

    // MARK: - 의심 URL scheme 목록 (기본 하드코딩 값)

    /// 탈옥 관련 앱의 URL scheme 목록 (하드코딩 기본값)
    /// canOpenURL은 Info.plist 화이트리스트가 필요하므로,
    /// 대신 해당 앱의 번들 경로 존재 여부로 대체 검사한다.
    private static let defaultSuspiciousSchemes: [String] = [
        "cydia://",
        "sileo://",
        "zbra://",
        "filza://",
        "undecimus://",
        "trollstore://",
    ]

    /// scheme에 대응하는 앱 경로 매핑 (FileManager 기반 대체 검사)
    private static let schemeAppPaths: [String: String] = [
        "cydia://": "/Applications/Cydia.app",
        "sileo://": "/Applications/Sileo.app",
        "zbra://": "/Applications/Zebra.app",
        "filza://": "/Applications/Filza.app",
        "undecimus://": "/Applications/unc0ver.app",
        "trollstore://": "/Applications/TrollStore.app",
    ]

    // MARK: - 동적 시그니처 (서버에서 수신한 값 + 기본값 병합)

    /// 실제 탐지에 사용되는 의심 경로 목록 (기본값 + 서버 동적 시그니처)
    static var suspiciousPaths: [String] = defaultSuspiciousPaths

    /// 실제 탐지에 사용되는 의심 URL scheme 목록 (기본값 + 서버 동적 시그니처)
    static var suspiciousSchemes: [String] = defaultSuspiciousSchemes

    // MARK: - 동적 시그니처 적용

    /// 서버에서 수신한 시그니처를 기존 하드코딩 목록에 병합한다.
    /// 기본 하드코딩 값은 유지하고, 서버 시그니처를 추가로 병합한다.
    /// 중복 값은 제거된다.
    ///
    /// - Parameter signatures: 서버에서 수신한 시그니처 항목 배열
    static func applySignatures(_ signatures: [SignatureItem]) {
        var dynamicPaths: [String] = []
        var dynamicSchemes: [String] = []

        for item in signatures {
            switch item.type {
            case "jailbreak_paths":
                // 탈옥 의심 파일/디렉토리 경로 추가
                dynamicPaths.append(item.value)
            case "jailbreak_url_schemes":
                // 탈옥 관련 URL scheme 추가
                dynamicSchemes.append(item.value)
            default:
                // 알 수 없는 시그니처 유형은 무시
                break
            }
        }

        // 기본 하드코딩 값에 서버 시그니처를 병합 (중복 제거)
        if !dynamicPaths.isEmpty {
            let merged = defaultSuspiciousPaths + dynamicPaths
            suspiciousPaths = Array(Set(merged))
        }

        if !dynamicSchemes.isEmpty {
            let merged = defaultSuspiciousSchemes + dynamicSchemes
            suspiciousSchemes = Array(Set(merged))
        }
    }

    // MARK: - 탐지 실행

    public func detect() -> DetectionResult {
        var checks: [String: String] = [:]

        // 1. Swift 레이어: 의심 파일 경로 존재 확인
        checks["suspicious_paths"] = checkSuspiciousPaths()

        // 2. Swift 레이어: URL scheme 대응 앱 존재 확인
        checks["url_schemes"] = checkUrlSchemes()

        // 3. Swift 레이어: 샌드박스 외부 쓰기 가능 확인
        checks["sandbox_write"] = checkSandboxIntegrity()

        // 4. C 네이티브: fork() 호출 가능 여부 (탈옥 시 fork 가능)
        let forkResult = native_check_fork()
        checks["fork_check"] = forkResult == 1 ? "detected" : "not_detected"

        // 5. C 네이티브: _dyld_image_count 비정상 dylib 로드 확인
        let dyldResult = native_check_dyld()
        checks["dyld_check"] = dyldResult == 1 ? "detected" : "not_detected"

        // 6. C 네이티브: /etc/fstab 등 심볼릭 링크 변조 확인
        let symlinkResult = native_check_symlinks()
        checks["symlink_check"] = symlinkResult == 1 ? "detected" : "not_detected"

        // 탐지 결과 계산
        let totalChecks = checks.count
        let detectedCount = checks.values.filter { $0.hasPrefix("detected") }.count
        let detected = detectedCount > 0
        let confidence = detected ? min(Float(detectedCount) / Float(totalChecks), 1.0) : 0.0

        #if DEBUG
        print("[GuardSDK DEBUG] [탈옥 탐지] suspiciousPaths=\(checks["suspicious_paths"]?.hasPrefix("detected") ?? false), urlSchemes=\(checks["url_schemes"] == "detected"), sandboxWrite=\(checks["sandbox_write"] == "detected"), fork=\(forkResult == 1), dyld=\(dyldResult == 1), symlink=\(symlinkResult == 1) → detected=\(detected) (confidence=\(confidence))")
        #endif

        return DetectionResult(
            type: .jailbreak,
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

    /// 의심 파일 경로 존재 확인
    /// FileManager.fileExists로 탈옥 관련 경로 16개를 순회 검사한다.
    private func checkSuspiciousPaths() -> String {
        let fileManager = FileManager.default
        var foundPaths: [String] = []
        for path in JailbreakDetector.suspiciousPaths {
            if fileManager.fileExists(atPath: path) {
                foundPaths.append(path)
            }
        }
        if !foundPaths.isEmpty {
            return "detected:\(foundPaths.joined(separator: ","))"
        }
        return "not_detected"
    }

    /// URL scheme 대응 앱 경로 존재 확인
    /// canOpenURL 대신 FileManager로 앱 경로를 직접 검사한다.
    private func checkUrlSchemes() -> String {
        let fileManager = FileManager.default
        for scheme in JailbreakDetector.suspiciousSchemes {
            if let appPath = JailbreakDetector.schemeAppPaths[scheme],
               fileManager.fileExists(atPath: appPath) {
                return "detected"
            }
        }
        return "not_detected"
    }

    /// 샌드박스 무결성 검사
    /// 탈옥된 기기에서는 샌드박스 외부("/private/jailbreak_test")에 파일 쓰기가 가능하다.
    /// 정상 기기에서는 쓰기 시도 시 권한 오류가 발생한다.
    private func checkSandboxIntegrity() -> String {
        let testPath = "/private/jailbreak_test"
        let testData = "jailbreak_check".data(using: .utf8)

        do {
            try testData?.write(to: URL(fileURLWithPath: testPath))
            // 쓰기 성공 = 샌드박스가 뚫림 → 탈옥 탐지
            // 테스트 파일 정리
            try? FileManager.default.removeItem(atPath: testPath)
            return "detected"
        } catch {
            // 쓰기 실패 = 정상 샌드박스 → 탈옥 아님
            return "not_detected"
        }
    }
}
