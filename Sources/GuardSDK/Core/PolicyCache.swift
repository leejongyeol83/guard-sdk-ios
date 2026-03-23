// PolicyCache.swift
// Guard SDK - 보안 정책 로컬 캐시
//
// 서버에서 수신한 보안 정책을 로컬에 저장한다.
// 서버 연결 실패 시 마지막으로 수신한 정책을 복원하여 사용한다.

import Foundation

/// 보안 정책을 로컬에 캐싱하는 클래스.
///
/// UserDefaults에 JSON 형태로 저장한다.
public class PolicyCache {

    // MARK: - 상수

    /// UserDefaults 저장 키 (정책 데이터)
    private static let policyCacheKey = "com.guard.sdk.policy.cache"

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
    /// - Parameter policy: 저장할 보안 정책
    /// - Returns: 저장 성공 여부
    @discardableResult
    public func save(_ policy: SecurityPolicy) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        do {
            let data = try JSONEncoder().encode(policy)
            userDefaults.set(data, forKey: PolicyCache.policyCacheKey)
            return true
        } catch {
            return false
        }
    }

    /// 저장된 보안 정책을 복원한다.
    ///
    /// - Returns: 저장된 보안 정책, 또는 nil
    public func load() -> SecurityPolicy? {
        lock.lock()
        defer { lock.unlock() }
        guard let data = userDefaults.data(forKey: PolicyCache.policyCacheKey) else {
            return nil
        }

        do {
            return try JSONDecoder().decode(SecurityPolicy.self, from: data)
        } catch {
            clearInternal()
            return nil
        }
    }

    /// 캐시를 삭제한다.
    public func clear() {
        lock.lock()
        defer { lock.unlock() }
        clearInternal()
    }

    /// 락 내부에서 호출되는 삭제 (재진입 방지)
    private func clearInternal() {
        userDefaults.removeObject(forKey: PolicyCache.policyCacheKey)
    }
}
