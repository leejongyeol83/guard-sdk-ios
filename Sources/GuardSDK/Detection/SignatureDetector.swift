// SignatureDetector.swift
// GuardSDK - 코드 서명 검증 모듈
//
// Apple Team ID를 기반으로 재서명 변조를 탐지한다.
// 재서명 시 Team ID가 반드시 바뀌므로 서버 등록값과 비교하여 탐지한다.
// App Store 배포 앱에서도 키체인 접근 그룹으로 Team ID를 읽을 수 있어
// 모든 배포 환경에서 동작한다.

import Foundation
import Security

/// 코드 서명 검증 탐지기
/// 런타임에서 앱의 Team ID를 추출하여
/// 서버에서 수신한 기대 Team ID와 비교한다.
public final class SignatureDetector: Detector {

    // MARK: - Detector 프로토콜

    public let type: DetectionType = .signature

    // MARK: - 서버 기대값

    /// 서버에서 수신한 예상 서명 해시 (iOS에서는 Team ID)
    /// nil이면 검증 스킵
    public var expectedSignatureHash: String?

    // MARK: - 탐지 실행

    public func detect() -> DetectionResult {
        var checks: [String: String] = [:]

        // 기대값이 없으면 검증 스킵 (정상 처리)
        guard let expectedHash = expectedSignatureHash, !expectedHash.isEmpty else {
            checks["signature_verify"] = "skipped"
            return DetectionResult(
                type: .signature,
                detected: false,
                confidence: 0.0,
                details: checks,
                timestamp: Date(),
                action: .log
            )
        }

        // 1. 런타임에서 Team ID 추출
        let currentTeamId = extractTeamId()
        checks["current_team_id"] = currentTeamId ?? "unavailable"
        checks["expected_team_id"] = expectedHash

        // 2. Team ID 비교
        if let currentTeamId = currentTeamId {
            if currentTeamId == expectedHash {
                checks["signature_verify"] = "match"
                #if DEBUG
                print("[GuardSDK DEBUG] [서명 탐지] teamIdMatch=true, currentTeamId=\(currentTeamId), hasExpectedHash=true → detected=false (confidence=0.0)")
                #endif
                return DetectionResult(
                    type: .signature,
                    detected: false,
                    confidence: 0.0,
                    details: checks,
                    timestamp: Date(),
                    action: .log
                )
            } else {
                checks["signature_verify"] = "mismatch"
                #if DEBUG
                print("[GuardSDK DEBUG] [서명 탐지] teamIdMatch=false, currentTeamId=\(currentTeamId), expectedTeamId=\(expectedHash) → detected=true (confidence=1.0)")
                #endif
                return DetectionResult(
                    type: .signature,
                    detected: true,
                    confidence: 1.0,
                    details: checks,
                    timestamp: Date(),
                    action: .log
                )
            }
        } else {
            // Team ID 추출 실패
            checks["signature_verify"] = "extraction_failed"
            #if DEBUG
            print("[GuardSDK DEBUG] [서명 탐지] teamIdExtraction=failed, hasExpectedHash=true → detected=true (confidence=0.8)")
            #endif
            return DetectionResult(
                type: .signature,
                detected: true,
                confidence: 0.8,
                details: checks,
                timestamp: Date(),
                action: .log
            )
        }
    }

    public func isAvailable() -> Bool {
        return true
    }

    // MARK: - Team ID 추출

    /// 런타임에서 앱의 Team ID를 추출한다.
    /// 우선순위:
    ///   1. 키체인 접근 그룹에서 추출 (모든 배포 환경에서 동작)
    ///   2. embedded.mobileprovision 폴백 (개발/AdHoc/Enterprise)
    private func extractTeamId() -> String? {
        // 방법 1: 키체인 임시 아이템으로 접근 그룹의 Team ID 추출
        // App Store 배포 앱에서도 동작한다
        if let teamId = extractTeamIdFromKeychain() {
            return teamId
        }

        // 방법 2: embedded.mobileprovision에서 TeamIdentifier 추출 (폴백)
        return extractTeamIdFromMobileProvision()
    }

    /// 키체인 임시 아이템을 생성하여 접근 그룹에서 Team ID를 추출한다.
    ///
    /// iOS 앱의 키체인 접근 그룹은 "<TeamID>.<BundleID>" 형식이다.
    /// 임시 아이템을 추가 → 접근 그룹 읽기 → 삭제 순서로 Team ID를 확보한다.
    /// App Store, Ad Hoc, Enterprise 등 모든 배포 환경에서 동작한다.
    private func extractTeamIdFromKeychain() -> String? {
        // 고유한 키로 임시 아이템 추가
        let tempAccount = "com.guard.teamid.probe"
        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: tempAccount,
            kSecValueData as String: Data("probe".utf8),
            kSecReturnAttributes as String: true,
        ]

        var result: AnyObject?
        let addStatus = SecItemAdd(addQuery as CFDictionary, &result)

        // 이미 존재하면 기존 것을 읽기
        if addStatus == errSecDuplicateItem {
            let readQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: tempAccount,
                kSecReturnAttributes as String: true,
            ]
            let readStatus = SecItemCopyMatching(readQuery as CFDictionary, &result)
            guard readStatus == errSecSuccess else { return nil }
        } else if addStatus != errSecSuccess {
            return nil
        }

        // 접근 그룹에서 Team ID 추출
        guard let attrs = result as? [String: Any],
              let accessGroup = attrs[kSecAttrAccessGroup as String] as? String else {
            // 정리: 임시 아이템 삭제
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: tempAccount,
            ]
            SecItemDelete(deleteQuery as CFDictionary)
            return nil
        }

        // 정리: 임시 아이템 삭제
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: tempAccount,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        // 접근 그룹 형식: "<TeamID>.<BundleID>" → "." 앞의 Team ID 추출
        let components = accessGroup.split(separator: ".", maxSplits: 1)
        guard let teamId = components.first, !teamId.isEmpty else {
            return nil
        }

        return String(teamId)
    }

    /// embedded.mobileprovision에서 TeamIdentifier를 추출한다. (폴백)
    /// App Store 배포 앱에서는 mobileprovision이 제거되므로 키체인 방식이 우선이다.
    private func extractTeamIdFromMobileProvision() -> String? {
        guard let provisionPath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision"),
              let provisionData = FileManager.default.contents(atPath: provisionPath) else {
            return nil
        }

        // CMS 래퍼에서 XML plist 영역 추출
        guard let plistData = extractPlistFromCMS(provisionData) else {
            return nil
        }

        guard let plist = try? PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any],
              let teamIds = plist["TeamIdentifier"] as? [String],
              let teamId = teamIds.first else {
            return nil
        }

        return teamId
    }

    /// CMS(PKCS#7) 서명된 데이터에서 XML plist 영역을 추출한다.
    private func extractPlistFromCMS(_ data: Data) -> Data? {
        guard let xmlStart = data.range(of: Data("<?xml".utf8)),
              let plistEnd = data.range(of: Data("</plist>".utf8)) else {
            return nil
        }
        let endIndex = plistEnd.upperBound
        guard xmlStart.lowerBound < endIndex else {
            return nil
        }
        return data.subdata(in: xmlStart.lowerBound..<endIndex)
    }
}
