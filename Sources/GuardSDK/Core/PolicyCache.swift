import Foundation

final class PolicyCache {
    private let defaults = UserDefaults.standard
    private let policyKey = "com.am.guard.policy"
    private let signaturesKey = "com.am.guard.signatures"
    private let timestampKey = "com.am.guard.cacheTimestamp"
    private let cacheTTL: TimeInterval = 24 * 60 * 60 // 24시간

    var isCacheValid: Bool {
        guard let timestamp = defaults.object(forKey: timestampKey) as? Date else { return false }
        return Date().timeIntervalSince(timestamp) < cacheTTL
    }

    func savePolicy(_ policy: GuardPolicy) {
        if let data = try? JSONEncoder().encode(policy) {
            defaults.set(data, forKey: policyKey)
            defaults.set(Date(), forKey: timestampKey)
        }
    }

    func loadPolicy() -> GuardPolicy? {
        guard let data = defaults.data(forKey: policyKey) else { return nil }
        return try? JSONDecoder().decode(GuardPolicy.self, from: data)
    }

    func saveSignatures(_ signatures: [GuardSignature]) {
        if let data = try? JSONEncoder().encode(signatures) {
            defaults.set(data, forKey: signaturesKey)
        }
    }

    func loadSignatures() -> [GuardSignature] {
        guard let data = defaults.data(forKey: signaturesKey) else { return [] }
        return (try? JSONDecoder().decode([GuardSignature].self, from: data)) ?? []
    }

    func clear() {
        defaults.removeObject(forKey: policyKey)
        defaults.removeObject(forKey: signaturesKey)
        defaults.removeObject(forKey: timestampKey)
    }
}
