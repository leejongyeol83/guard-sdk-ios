import Foundation

final class DetectionReporter {
    private let apiClient: ApiClient
    private var pendingDetections: [[String: Any]] = []
    private let batchSize = 5
    private let batchInterval: TimeInterval = 30
    private var lastSendTime = Date()
    private let offlineKey = "com.am.guard.offlineDetections"

    init(apiClient: ApiClient) {
        self.apiClient = apiClient
        loadOffline()
    }

    func add(_ result: DetectionResult) {
        var detection: [String: Any] = [
            "detectionType": result.type.rawValue,
            "severity": result.severity.rawValue,
        ]
        if let details = result.details { detection["details"] = details }
        pendingDetections.append(detection)

        if pendingDetections.count >= batchSize || Date().timeIntervalSince(lastSendTime) >= batchInterval {
            flush()
        }
    }

    func flush() {
        guard !pendingDetections.isEmpty else { return }
        let toSend = pendingDetections
        pendingDetections = []
        lastSendTime = Date()

        let deviceId = UIDevice.current.identifierForVendor?.uuidString ?? UUID().uuidString
        let osVersion = UIDevice.current.systemVersion
        let deviceModel = UIDevice.current.model

        Task {
            do {
                _ = try await apiClient.report(
                    deviceId: deviceId, platform: "ios",
                    appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0",
                    osVersion: osVersion, deviceModel: deviceModel, detections: toSend
                )
                clearOffline()
            } catch {
                pendingDetections.insert(contentsOf: toSend, at: 0)
                saveOffline()
            }
        }
    }

    private func saveOffline() {
        if let data = try? JSONSerialization.data(withJSONObject: pendingDetections) {
            UserDefaults.standard.set(data, forKey: offlineKey)
        }
    }

    private func loadOffline() {
        guard let data = UserDefaults.standard.data(forKey: offlineKey),
              let array = try? JSONSerialization.jsonObject(with: data) as? [[String: Any]] else { return }
        pendingDetections = array
    }

    private func clearOffline() {
        UserDefaults.standard.removeObject(forKey: offlineKey)
    }
}
