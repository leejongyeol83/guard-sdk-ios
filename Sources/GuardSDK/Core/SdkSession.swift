// SdkSession.swift
// Anti-Mobile Service iOS SDK - 세션 토큰 관리 (Keychain 기반)
//
// 서버에서 발급된 세션 토큰을 Keychain에 안전하게 저장하고,
// TTL 기반으로 만료를 관리한다.
// 앱 재시작 시에도 토큰이 유지되어 재초기화 없이 사용할 수 있다.

import Foundation
import Security

/// Keychain 기반 세션 토큰 관리 클래스.
///
/// 세션 토큰과 만료 시간을 Keychain에 암호화하여 저장한다.
/// SecItemAdd/SecItemCopyMatching/SecItemDelete API를 직접 사용한다.
public class SdkSession {

    // MARK: - 상수

    /// Keychain 서비스 식별자
    private static let keychainService = "com.guard.sdk.session"

    /// 세션 토큰 저장 키
    private static let tokenKey = "session_token"

    /// 만료 시간 저장 키
    private static let expiresAtKey = "session_expires_at"

    /// 기본 TTL (24시간)
    public static let defaultTTL: TimeInterval = 24 * 60 * 60

    // MARK: - 공개 메서드

    /// 세션 토큰을 Keychain에 저장한다.
    ///
    /// 이미 저장된 토큰이 있으면 삭제 후 새로 저장한다.
    ///
    /// - Parameters:
    ///   - token: 서버에서 발급된 세션 토큰
    ///   - ttl: 토큰 유효 기간 (초, 기본: 24시간)
    @discardableResult
    public func saveToken(_ token: String, ttl: TimeInterval = SdkSession.defaultTTL) -> Bool {
        // 기존 토큰 삭제
        deleteKeychainItem(key: SdkSession.tokenKey)
        deleteKeychainItem(key: SdkSession.expiresAtKey)

        // 토큰 저장
        guard saveKeychainItem(key: SdkSession.tokenKey, value: token) else {
            return false
        }

        // 만료 시간 저장 (현재 시간 + TTL)
        let expiresAt = Date().addingTimeInterval(ttl)
        let expiresAtString = String(expiresAt.timeIntervalSince1970)
        guard saveKeychainItem(key: SdkSession.expiresAtKey, value: expiresAtString) else {
            // 토큰은 저장했지만 만료 시간 저장 실패 시 정리
            deleteKeychainItem(key: SdkSession.tokenKey)
            return false
        }

        return true
    }

    /// 저장된 세션 토큰을 반환한다.
    ///
    /// 토큰이 없거나 만료된 경우 nil을 반환한다.
    ///
    /// - Returns: 유효한 세션 토큰, 또는 nil
    public func getToken() -> String? {
        // 만료 확인
        guard !isExpired() else {
            // 만료된 토큰은 정리
            clear()
            return nil
        }

        return loadKeychainItem(key: SdkSession.tokenKey)
    }

    /// 세션 토큰이 만료되었는지 확인한다.
    ///
    /// 만료 시간 정보가 없거나, 현재 시간이 만료 시간을 넘었으면 true를 반환한다.
    ///
    /// - Returns: 만료 여부
    public func isExpired() -> Bool {
        guard let expiresAtString = loadKeychainItem(key: SdkSession.expiresAtKey),
              let expiresAtTimestamp = Double(expiresAtString) else {
            // 만료 시간 정보가 없으면 만료된 것으로 처리
            return true
        }

        let expiresAt = Date(timeIntervalSince1970: expiresAtTimestamp)
        return Date() >= expiresAt
    }

    /// 저장된 세션 정보를 모두 삭제한다.
    ///
    /// 토큰과 만료 시간을 Keychain에서 삭제한다.
    public func clear() {
        deleteKeychainItem(key: SdkSession.tokenKey)
        deleteKeychainItem(key: SdkSession.expiresAtKey)
    }

    // MARK: - Keychain 헬퍼 (비공개)

    /// Keychain에 문자열 값을 저장한다.
    @discardableResult
    private func saveKeychainItem(key: String, value: String) -> Bool {
        guard let data = value.data(using: .utf8) else { return false }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: SdkSession.keychainService,
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
            kSecAttrService as String: SdkSession.keychainService,
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
            kSecAttrService as String: SdkSession.keychainService,
            kSecAttrAccount as String: key,
        ]

        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
