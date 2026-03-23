// IntegrityDetector.swift
// GuardSDK
//
// [CL-13] 앱 무결성 검증 모듈
// 앱 바이너리 해시와 코드 서명 무결성을 검증한다.
// Swift 레이어에서 해시 계산, C 네이티브에서 Mach-O 로드 커맨드를 검사한다.

import Foundation
import CommonCrypto
@_implementationOnly import GuardNative

/// 앱 무결성 탐지기
/// 5개 검사 항목(Swift 3개 + C 네이티브 2개)을 실행하여
/// 앱 바이너리 변조 여부를 판별한다.
public final class IntegrityDetector: Detector {

    // MARK: - Detector 프로토콜

    public let type: DetectionType = .integrity

    // MARK: - 서버 기대 해시값

    /// 서버에서 수신한 예상 바이너리 해시 (nil이면 해시 비교 스킵)
    public var expectedBinaryHash: String?

    /// 서버에서 수신한 예상 서명 해시 (nil이면 서명 비교 스킵)
    public var expectedSignatureHash: String?

    // MARK: - 탐지 실행

    public func detect() -> DetectionResult {
        var checks: [String: String] = [:]

        // 1. Swift 레이어: embedded.mobileprovision 존재 확인
        // 프로비저닝 프로파일이 없으면 비정상 배포 (탈옥 앱 또는 변조)
        checks["mobileprovision"] = checkMobileProvision()

        // 2. Swift 레이어: Info.plist 변조 확인
        // Bundle.main.infoDictionary에서 필수 키 존재 여부를 검증한다.
        checks["info_plist"] = checkInfoPlistIntegrity()

        // 3. Swift 레이어: Bundle 실행 파일 해시 계산 (CommonCrypto SHA-256)
        // 실행 파일의 SHA-256 해시를 계산하여 details에 포함한다.
        checks["binary_hash"] = checkBinaryHash()

        // 4. C 네이티브: LC_CODE_SIGNATURE 로드 커맨드 검증
        // Mach-O 헤더에서 코드 서명 로드 커맨드가 존재하는지 확인한다.
        // 시뮬레이터에서는 코드 서명이 없을 수 있으므로 결과를 무시한다.
        let codeSignResult = native_check_code_signature()
        #if targetEnvironment(simulator)
        checks["code_signature"] = "skipped_simulator"
        #else
        checks["code_signature"] = codeSignResult == 1 ? "detected" : "not_detected"
        #endif

        // 5. C 네이티브: LC_ENCRYPTION_INFO_64 확인 (암호화 해제 여부)
        // App Store에서 배포된 앱은 FairPlay DRM으로 암호화된다.
        // 복호화된(크랙된) 앱은 encryption_info가 0으로 설정된다.
        // App Store 배포가 아닌 경우(개발/AdHoc/Enterprise) 암호화가 없는 게 정상이므로 스킵.
        let encryptionResult = native_check_encryption()
        if isAppStoreEnvironment() {
            checks["encryption_info"] = encryptionResult == 1 ? "detected" : "not_detected"
        } else {
            checks["encryption_info"] = "skipped_non_appstore"
        }

        // 탐지 결과 계산
        let totalChecks = checks.count
        let detectedCount = checks.values.filter { $0 == "detected" }.count
        let detected = detectedCount > 0
        let confidence = detected ? min(Float(detectedCount) / Float(totalChecks), 1.0) : 0.0

        return DetectionResult(
            type: .integrity,
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

    // MARK: - 환경 판별

    /// App Store 환경인지 판별한다.
    /// embedded.mobileprovision이 없으면 App Store 배포 (Apple이 제거함).
    /// 개발/AdHoc/Enterprise 배포에서는 mobileprovision이 존재한다.
    private func isAppStoreEnvironment() -> Bool {
        return Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") == nil
    }

    // MARK: - Swift 검사 메서드

    /// embedded.mobileprovision 존재 확인
    /// App Store 배포 앱은 이 파일이 존재하지 않는다 (Apple이 제거).
    /// 개발/AdHoc/Enterprise 배포에서는 존재한다.
    /// 파일이 없는데 App Store 환경이 아니면 변조 가능성이 있다.
    private func checkMobileProvision() -> String {
        guard let provisionPath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision") else {
            // embedded.mobileprovision이 없음
            // DEBUG 빌드: Xcode 개발 환경에서는 없는 게 정상
            // RELEASE 빌드: App Store 배포에서도 없는 게 정상 (Apple이 제거)
            // → 프로비저닝 파일 부재만으로는 변조를 판단할 수 없음
            return "not_detected"
        }

        // 파일이 존재하면 정상 프로비저닝 상태 (AdHoc/Enterprise 배포)
        // 추가로 파일 크기가 비정상적으로 작으면 변조 의심
        let fileManager = FileManager.default
        if let attributes = try? fileManager.attributesOfItem(atPath: provisionPath),
           let fileSize = attributes[.size] as? UInt64,
           fileSize < 100 {
            // 비정상적으로 작은 프로비저닝 파일 → 변조 의심
            return "detected"
        }

        return "not_detected"
    }

    /// Info.plist 변조 확인
    /// Bundle.main.infoDictionary에서 필수 키(CFBundleIdentifier, CFBundleExecutable)의
    /// 존재 여부를 검증한다. 없으면 변조된 것으로 판단한다.
    private func checkInfoPlistIntegrity() -> String {
        guard let infoDict = Bundle.main.infoDictionary else {
            // Info.plist를 읽을 수 없음 → 변조 가능성
            return "detected"
        }

        // 필수 키 존재 확인
        let requiredKeys = [
            "CFBundleIdentifier",
            "CFBundleExecutable",
            "CFBundleVersion",
            "CFBundleShortVersionString",
        ]

        for key in requiredKeys {
            guard let value = infoDict[key] as? String, !value.isEmpty else {
                // 필수 키가 없거나 빈 값 → 변조 의심
                return "detected"
            }
        }

        return "not_detected"
    }

    /// Bundle 실행 파일의 __TEXT 세그먼트 SHA-256 해시를 계산한다.
    /// 전체 바이너리가 아닌 __TEXT 세그먼트만 해시하여 서버와 동일한 비교를 수행한다.
    /// 스토어 재서명 후에도 __TEXT 영역은 변경되지 않으므로 무결성 검증에 적합하다.
    private func checkBinaryHash() -> String {
        guard let executablePath = Bundle.main.executablePath else {
            // 실행 파일 경로를 가져올 수 없음 (비정상적이지만 해시 비교 불가이므로 스킵)
            return "skipped_no_path"
        }

        guard let binaryData = FileManager.default.contents(atPath: executablePath) else {
            // 바이너리 읽기 실패 (스킵)
            return "skipped_read_failed"
        }

        // __TEXT 세그먼트 추출 후 해시
        // FAT 바이너리 등 지원하지 않는 포맷이면 nil 반환
        guard let textSegment = extractTextSegment(from: binaryData) else {
            return "skipped_unsupported_format"
        }

        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        textSegment.withUnsafeBytes { bufferPointer in
            _ = CC_SHA256(bufferPointer.baseAddress, CC_LONG(textSegment.count), &hash)
        }

        let hashString = hash.map { String(format: "%02x", $0) }.joined()

        if let expected = expectedBinaryHash, !expected.isEmpty {
            if hashString.lowercased() != expected.lowercased() {
                return "detected"
            }
        }

        return "hash:\(hashString)"
    }

    /// Mach-O 바이너리에서 __TEXT 세그먼트 데이터를 추출한다.
    private func extractTextSegment(from binary: Data) -> Data? {
        guard binary.count >= 32 else { return nil }

        // Mach-O 64-bit magic: 0xFEEDFACF
        let magic: UInt32 = binary.withUnsafeBytes { $0.load(as: UInt32.self) }
        guard magic == 0xFEEDFACF else { return nil }

        // mach_header_64: ncmds at offset 16
        let ncmds: UInt32 = binary.withUnsafeBytes {
            $0.load(fromByteOffset: 16, as: UInt32.self)
        }

        // 로드 커맨드 시작: mach_header_64 크기 = 32 bytes
        var cmdOffset = 32
        let lcSegment64: UInt32 = 0x19

        for _ in 0..<ncmds {
            guard cmdOffset + 8 <= binary.count else { break }

            let cmd: UInt32 = binary.withUnsafeBytes {
                $0.load(fromByteOffset: cmdOffset, as: UInt32.self)
            }
            let cmdsize: UInt32 = binary.withUnsafeBytes {
                $0.load(fromByteOffset: cmdOffset + 4, as: UInt32.self)
            }

            if cmd == lcSegment64 {
                // segment_command_64: segname at offset +8, 16 bytes
                let segnameData = binary.subdata(in: (cmdOffset + 8)..<(cmdOffset + 24))
                let segname = String(data: segnameData.prefix(while: { $0 != 0 }), encoding: .ascii) ?? ""

                if segname == "__TEXT" {
                    // segment_command_64: cmd(4)+cmdsize(4)+segname(16)+vmaddr(8)+vmsize(8)+fileoff(8)+filesize(8)
                    // fileoff at offset +40, filesize at offset +48
                    let fileoff: UInt64 = binary.withUnsafeBytes {
                        $0.load(fromByteOffset: cmdOffset + 40, as: UInt64.self)
                    }
                    let filesize: UInt64 = binary.withUnsafeBytes {
                        $0.load(fromByteOffset: cmdOffset + 48, as: UInt64.self)
                    }

                    let start = Int(fileoff)
                    let end = start + Int(filesize)
                    guard end <= binary.count else { return nil }

                    return binary.subdata(in: start..<end)
                }
            }

            cmdOffset += Int(cmdsize)
        }

        return nil
    }
}
