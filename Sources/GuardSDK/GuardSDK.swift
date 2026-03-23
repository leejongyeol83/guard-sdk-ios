import UIKit

public protocol GuardDelegate: AnyObject {
    func guardSDK(_ sdk: GuardSDK, didDetect result: DetectionResult, action: DetectionAction)
    func guardSDK(_ sdk: GuardSDK, didFailWithError error: Error)
}

public final class GuardSDK {
    public static let shared = GuardSDK()

    public private(set) var isInitialized = false
    public private(set) var isDetecting = false
    public weak var delegate: GuardDelegate?

    private var config: GuardConfig?
    private var apiClient: ApiClient?
    private var policyCache = PolicyCache()
    private var engine = DetectionEngine()
    private var reporter: DetectionReporter?
    private var timer: DispatchSourceTimer?

    private init() {}

    // MARK: - Public API

    public func initialize(config: GuardConfig, delegate: GuardDelegate? = nil, completion: @escaping (Bool) -> Void) {
        self.config = config
        self.delegate = delegate
        self.apiClient = ApiClient(serverUrl: config.serverUrl, apiKey: config.apiKey)
        self.reporter = DetectionReporter(apiClient: apiClient!)

        Task {
            do {
                let initData = try await apiClient!.initialize(
                    platform: "ios",
                    osVersion: UIDevice.current.systemVersion,
                    deviceModel: UIDevice.current.model,
                    appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "0.0.0"
                )

                engine.updatePolicy(initData.policy, signatures: initData.signatures)
                policyCache.savePolicy(initData.policy)
                policyCache.saveSignatures(initData.signatures)

                isInitialized = true
                DispatchQueue.main.async { completion(true) }
            } catch {
                // 오프라인: 캐시 사용
                if let cached = policyCache.loadPolicy() {
                    engine.updatePolicy(cached, signatures: policyCache.loadSignatures())
                    isInitialized = true
                    DispatchQueue.main.async { completion(true) }
                } else {
                    DispatchQueue.main.async {
                        delegate?.guardSDK(self, didFailWithError: error)
                        completion(false)
                    }
                }
            }
        }
    }

    public func startDetection() {
        guard isInitialized, let config = config else { return }
        isDetecting = true

        let queue = DispatchQueue(label: "com.am.guard.detection")
        timer = DispatchSource.makeTimerSource(queue: queue)
        timer?.schedule(deadline: .now(), repeating: .seconds(config.detectionInterval))
        timer?.setEventHandler { [weak self] in self?.runDetection() }
        timer?.resume()
    }

    public func stopDetection() {
        timer?.cancel()
        timer = nil
        isDetecting = false
        reporter?.flush()
    }

    public func runDetection() {
        guard isInitialized, let config = config else { return }

        let results = engine.runAll(config: config)
        let policy = policyCache.loadPolicy()

        for result in results {
            let actionStr = policy?.detectionActions[result.type.rawValue] ?? "log_only"
            let action = DetectionAction(rawValue: actionStr) ?? .logOnly

            reporter?.add(result)

            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.delegate?.guardSDK(self, didDetect: result, action: action)
            }
        }
    }

    public func refreshPolicy() {
        guard let apiClient = apiClient else { return }

        Task {
            do {
                let policy = try await apiClient.fetchPolicy()
                let signatures = try await apiClient.fetchSignatures(platform: "ios")
                engine.updatePolicy(policy, signatures: signatures)
                policyCache.savePolicy(policy)
                policyCache.saveSignatures(signatures)
            } catch {
                // 갱신 실패 — 기존 캐시 유지
            }
        }
    }

    public func stop() {
        stopDetection()
        isInitialized = false
        config = nil
        apiClient = nil
        reporter = nil
        policyCache.clear()
    }
}
