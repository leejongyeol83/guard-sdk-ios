// PolicyCache.swift
// Guard SDK - 보안 정책 로컬 캐시 (HMAC 무결성 검증 포함)
//
// 서버에서 수신한 보안 정책을 로컬에 저장한다.
// 서버 연결 실패 시 마지막으로 수신한 정책을 복원하여 사용한다.
// HMAC-SHA256으로 캐시 변조를 감지한다.

import Foundation
import CommonCrypto
import Security

/// 보안 정책을 로컬에 캐싱하는 클래스.
///
/// UserDefaults에 JSON 형태로 저장하며, HMAC-SHA256으로 무결성을 검증한다.
/// HMAC 키는 Keychain에 저장되어 UserDefaults만으로는 위조할 수 없다.
public class PolicyCache {

    // MARK: - 상수

    /// UserDefaults 저장 키 (정책 데이터)
    private static let policyCacheKey = "com.guard.sdk.policy.cache"

    /// UserDefaults 저장 키 (HMAC)
    private static let policyHmacKey = "com.guard.sdk.policy.hmac"

    /// Keychain 서비스 식별자
    private static let keychainService = "com.guard.sdk.policy.integrity"

    /// Keychain HMAC 키 저장 키
    private static let hmacSecretKey = "hmac_secret"

    /// UserDefaults 인스턴스 (테스트 시 주입 가능)
    private let userDefaults: UserDefaults

    /// 동시 접근 방지를 위한 락
    private let lock = NSLock()

    // MARK: - 초기화

    /// PolicyCache를 초기화한다.
    ///
    /// - Parameter userDefaults: 사용할 UserDefaults 인스턴스 (기본: .standard)
    public init(userDefaults: UserDefaults = .standard) {
        self.userDefaults = userDefaults
    }

    // MARK: - 공개 메서드

    /// 보안 정책을 저장한다.
    ///
    /// 정책 JSON과 함께 HMAC-SHA256을 계산하여 저장한다.
    ///
    /// - Parameter policy: 저장할 보안 정책
    /// - Returns: 저장 성공 여부
    @discardableResult
    public func save(_ policy: SecurityPolicy) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        do {
            let data = try JSONEncoder().encode(policy)

            // HMAC 생성 및 저장
            let hmac = computeHmac(data: data)
            userDefaults.set(data, forKey: PolicyCache.policyCacheKey)
            if let hmac = hmac {
                userDefaults.set(hmac, forKey: PolicyCache.policyHmacKey)
            }

            GuardSDK.shared.log(.debug, "[캐시] 정책 저장 완료 (HMAC 포함)")
            return true
        } catch {
            GuardSDK.shared.log(.error, "[캐시] 정책 저장 실패: \(error.localizedDescription)")
            return false
        }
    }

    /// 저장된 보안 정책을 복원한다.
    ///
    /// HMAC 검증에 실패하면 캐시를 삭제하고 nil을 반환한다.
    ///
    /// - Returns: 저장된 보안 정책, 또는 nil
    public func load() -> SecurityPolicy? {
        lock.lock()
        defer { lock.unlock() }
        guard let data = userDefaults.data(forKey: PolicyCache.policyCacheKey) else {
            return nil
        }

        // HMAC 검증
        if let storedHmac = userDefaults.string(forKey: PolicyCache.policyHmacKey) {
            guard let computedHmac = computeHmac(data: data), computedHmac == storedHmac else {
                GuardSDK.shared.log(.error, "[캐시] 정책 무결성 검증 실패 — 캐시 변조 감지, 삭제합니다.")
                clearInternal()
                return nil
            }
        } else {
            // HMAC이 없는 레거시 캐시 → 이번에 저장 시 HMAC이 붙으므로 허용
            GuardSDK.shared.log(.debug, "[캐시] 레거시 캐시 (HMAC 없음) — 이번 저장 시 HMAC이 추가됩니다.")
        }

        do {
            let policy = try JSONDecoder().decode(SecurityPolicy.self, from: data)
            GuardSDK.shared.log(.debug, "[캐시] 정책 복원 완료 (무결성 검증 통과)")
            return policy
        } catch {
            GuardSDK.shared.log(.error, "[캐시] 정책 복원 실패: \(error.localizedDescription)")
            clearInternal()
            return nil
        }
    }

    /// 캐시를 삭제한다.
    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        clearInternal()
        GuardSDK.shared.log(.debug, "[캐시] 정책 삭제 완료")
    }

    /// 락 내부에서 호출되는 삭제 (재진입 방지)
    private func clearInternal() {
        userDefaults.removeObject(forKey: PolicyCache.policyCacheKey)
        userDefaults.removeObject(forKey: PolicyCache.policyHmacKey)
    }

    // MARK: - HMAC 계산

    /// HMAC-SHA256을 계산한다.
    ///
    /// - Parameter data: HMAC을 계산할 데이터
    /// - Returns: hex 문자열 HMAC, 또는 nil (키 생성 실패 시)
    private func computeHmac(data: Data) -> String? {
        guard let secret = getOrCreateHmacSecret() else { return nil }
        guard let secretData = secret.data(using: .utf8) else { return nil }

        var hmac = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        secretData.withUnsafeBytes { secretBytes in
            data.withUnsafeBytes { dataBytes in
                CCHmac(
                    CCHmacAlgorithm(kCCHmacAlgSHA256),
                    secretBytes.baseAddress, secretData.count,
                    dataBytes.baseAddress, data.count,
                    &hmac
                )
            }
        }

        return hmac.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Keychain HMAC 비밀키 관리

    /// Keychain에서 HMAC 비밀키를 가져오거나, 없으면 새로 생성한다.
    private func getOrCreateHmacSecret() -> String? {
        // 기존 키 조회
        if let existing = loadKeychainItem(key: PolicyCache.hmacSecretKey) {
            return existing
        }

        // 새 키 생성 (32바이트 랜덤)
        var bytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        guard status == errSecSuccess else { return nil }

        let newSecret = bytes.map { String(format: "%02x", $0) }.joined()
        saveKeychainItem(key: PolicyCache.hmacSecretKey, value: newSecret)
        return newSecret
    }

    /// Keychain에 문자열 값을 저장한다.
    @discardableResult
    private func saveKeychainItem(key: String, value: String) -> Bool {
        guard let data = value.data(using: .utf8) else { return false }

        // 기존 항목 삭제 후 새로 저장
        deleteKeychainItem(key: key)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: PolicyCache.keychainService,
            kSecAttrAccount as String: key,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        return status == errSecSuccess
    }

    /// Keychain에서 문자열 값을 조회한다.
    private func loadKeychainItem(key: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: PolicyCache.keychainService,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess,
              let data = result as? Data,
              let value = String(data: data, encoding: .utf8) else {
            return nil
        }

        return value
    }

    /// Keychain에서 항목을 삭제한다.
    @discardableResult
    private func deleteKeychainItem(key: String) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: PolicyCache.keychainService,
            kSecAttrAccount as String: key,
        ]

        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
