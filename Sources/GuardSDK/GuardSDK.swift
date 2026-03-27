// GuardSDK.swift
// Guard SDK - 공개 API 싱글톤 진입점
//
// 호스트 앱에서 SDK를 초기화하고 보안 탐지를 관리하는 메인 클래스.
// 모든 공개 API는 이 클래스를 통해 접근한다.

import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// Guard SDK의 공개 진입점.
/// 싱글톤 패턴으로 앱 전체에서 하나의 인스턴스만 사용한다.
///
/// 사용 예시:
/// ```swift
/// let config = GuardConfig.Builder(apiKey: "your-key", appId: "com.example.app")
///     .serverUrl("https://api.example.com")
///     .build()
/// GuardSDK.shared.initialize(config: config, delegate: self)
/// GuardSDK.shared.startDetection()
/// ```
public final class GuardSDK {

    // MARK: - 버전 정보

    /// SDK 버전
    public static let sdkVersion = "1.0.0"

    // MARK: - 싱글톤

    /// 공유 싱글톤 인스턴스
    public static let shared = GuardSDK()

    /// 외부에서 인스턴스 생성 방지
    private init() {}

    // MARK: - 공개 프로퍼티

    /// SDK 초기화 완료 여부 (스레드 안전)
    private var _isInitialized: Bool = false
    public var isInitialized: Bool { sdkQueue.sync { _isInitialized } }

    /// 주기적 탐지 실행 중 여부 (스레드 안전)
    private var _isDetecting: Bool = false
    public var isDetecting: Bool { sdkQueue.sync { _isDetecting } }

    /// 탐지 결과를 전달받을 delegate (약한 참조)
    public weak var delegate: DetectionDelegate?

    // MARK: - 내부 컴포넌트

    /// SDK 설정 정보
    private var config: GuardConfig?

    /// 보안 정책 로컬 캐시
    private var policyCache: PolicyCache?

    /// 정책 기반 탐지 실행 엔진
    private var policyEngine: PolicyEngine?

    /// API 클라이언트
    private var apiClient: SdkApiClient?

    /// 탐지 결과 리포터 (배치 전송 + 재시도 + 오프라인 저장)
    private var reporter: DetectionReporter?

    /// 현재 디바이스 ID (리포트 전송에 사용)
    private var currentDeviceId: String?

    /// 주기적 탐지 타이머
    private var detectionTimer: Timer?

    /// 동시 접근 방지를 위한 직렬 큐
    private let sdkQueue = DispatchQueue(label: "com.guard.sdk.main", qos: .userInitiated)

    // MARK: - 공개 메서드: 초기화

    /// SDK를 초기화한다 (탐지는 시작하지 않음).
    ///
    /// 내부적으로 서버에서 세션 토큰과 정책을 수신한다.
    /// 초기화 완료 후 startDetection()을 호출하여 탐지를 시작한다.
    ///
    /// - Parameters:
    ///   - config: SDK 설정 정보 (API 키, 앱 ID 등)
    ///   - delegate: 탐지 결과를 전달받을 delegate (선택)
    ///   - completion: 초기화 완료 시 메인 스레드에서 호출 (성공 여부)
    public func initialize(config: GuardConfig, delegate: DetectionDelegate? = nil, completion: ((Bool) -> Void)? = nil) {
        sdkQueue.async { [weak self] in
            guard let self = self else {
                DispatchQueue.main.async { completion?(false) }
                return
            }

            // 이미 초기화된 경우 중복 방지
            guard !self._isInitialized else {
                self.log(.warn, "[초기화] SDK가 이미 초기화되어 있습니다. stop() 후 다시 호출하세요.")
                DispatchQueue.main.async { completion?(true) }
                return
            }

            self.config = config
            self.delegate = delegate

            // 1. 정책 캐시 초기화
            self.policyCache = PolicyCache()

            // 2. 정책 엔진 초기화 + Config 기반 탐지기 자동 등록
            let engine = PolicyEngine()
            self.registerDetectors(engine: engine, config: config)
            self.policyEngine = engine

            // 3. GuardConfig 기반 초기 정책 적용 (서버 정책 수신 전 기본 정책)
            let initialPolicy = self.createPolicyFromConfig(config)
            engine.applyPolicy(initialPolicy)
            self.log(.info, "[정책] GuardConfig 기반 초기 정책 적용 완료")

            // 4. 캐시된 정책이 있으면 덮어쓰기 (GuardConfig보다 우선)
            if let cachedPolicy = self.policyCache?.load() {
                engine.applyPolicy(cachedPolicy)
                if !cachedPolicy.detectionSignatures.isEmpty {
                    engine.applySignatures(cachedPolicy.detectionSignatures)
                }
                self.log(.info, "[정책] 캐시된 보안 정책 적용 완료")
            }

            // 5. API 클라이언트 초기화
            self.apiClient = SdkApiClient(serverUrl: config.serverUrl, apiKey: config.apiKey, config: config)

            // 6. 초기화 완료 표시
            self._isInitialized = true
            self.log(.info, "[초기화] SDK 초기화 완료 (apiKey: \(config.apiKey.prefix(8))..., 탐지기: \(engine.detectorCount)개)")

            // 7. 완료 콜백 (메인 스레드)
            DispatchQueue.main.async { completion?(true) }

            // 8. 서버에서 정책 수신 (비동기)
            self.fetchPolicyFromServer()
        }
    }

    /// [하위 호환] start()는 initialize()와 동일하게 동작한다.
    public func start(config: GuardConfig, delegate: DetectionDelegate? = nil, completion: ((Bool) -> Void)? = nil) {
        initialize(config: config, delegate: delegate, completion: completion)
    }

    // MARK: - 공개 메서드: 탐지 제어

    /// 주기적 보안 탐지를 시작한다.
    ///
    /// initialize() 완료 후 호출해야 한다.
    /// Config의 detectionInterval 주기로 탐지를 반복 실행한다.
    public func startDetection() {
        sdkQueue.async { [weak self] in
            guard let self = self else { return }

            guard self._isInitialized else {
                self.log(.warn, "[탐지] SDK가 초기화되지 않아 탐지를 시작할 수 없습니다.")
                self.delegate?.guardSDK(
                    self,
                    didEncounterError: .initializationFailed("SDK가 초기화되지 않았습니다.")
                )
                return
            }

            guard !self._isDetecting else {
                self.log(.warn, "[탐지] 탐지가 이미 실행 중입니다.")
                return
            }

            let interval = self.config?.detectionInterval ?? 60

            // 메인 스레드에서 Timer 생성 (RunLoop 필요)
            DispatchQueue.main.async {
                // 즉시 1회 실행 (sdkQueue에서 실행하여 메인 스레드 블로킹 방지)
                self.sdkQueue.async { self.performDetection() }

                // Timer 기반 주기적 실행 (탐지는 sdkQueue에서 수행)
                self.detectionTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
                    self?.sdkQueue.async { self?.performDetection() }
                }
                self._isDetecting = true
                self.log(.info, "[탐지] 주기적 탐지 시작 (주기: \(interval)초)")

                // 주기적 탐지 시 리포터 자동 플러시 타이머도 시작
                self.reporter?.startAutoFlush()

                // 화면 캡처 옵저버 시작
                if let screenDetector = self.policyEngine?.getDetector(for: .screenCapture) as? ScreenCaptureDetector {
                    screenDetector.startObserving()
                    self.log(.debug, "[화면보호] 캡처 옵저버 시작")
                }

                // 오프라인 저장된 탐지 이벤트 복구 전송
                if let reporter = self.reporter {
                    Task { await reporter.flushOfflineEvents() }
                }
            }
        }
    }

    /// 주기적 보안 탐지를 중지한다 (SDK는 유지).
    ///
    /// 탐지만 중지하고 SDK 초기화 상태는 유지한다.
    /// 다시 startDetection()으로 재개할 수 있다.
    public func stopDetection() {
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }

            self.detectionTimer?.invalidate()
            self.detectionTimer = nil
            self._isDetecting = false

            // 화면 캡처 옵저버 중지
            if let screenDetector = self.policyEngine?.getDetector(for: .screenCapture) as? ScreenCaptureDetector {
                screenDetector.stopObserving()
            }

            self.log(.info, "[탐지] 주기적 탐지 중지됨 (SDK 초기화 상태 유지)")
        }
    }

    /// 즉시 보안 탐지를 1회 실행한다.
    ///
    /// initialize()로 초기화된 이후에만 동작한다.
    /// 탐지 결과는 delegate를 통해 전달된다.
    public func runDetection() {
        sdkQueue.async { [weak self] in
            self?.performDetection()
        }
    }

    /// SDK를 완전히 종료하고 리소스를 해제한다.
    ///
    /// 탐지 중지 + 내부 상태 초기화.
    /// 다시 사용하려면 initialize()를 재호출해야 한다.
    public func stop() {
        sdkQueue.async { [weak self] in
            guard let self = self else { return }

            guard self._isInitialized else {
                self.log(.warn, "[초기화] SDK가 초기화되지 않았습니다.")
                return
            }

            // 화면 캡처 옵저버 중지
            if let screenDetector = self.policyEngine?.getDetector(for: .screenCapture) as? ScreenCaptureDetector {
                screenDetector.stopObserving()
            }

            // 메인 스레드 리소스 해제 (동기 실행으로 순서 보장)
            DispatchQueue.main.sync {
                self.detectionTimer?.invalidate()
                self.detectionTimer = nil
            }

            // 내부 상태 정리
            self.reporter?.shutdown()
            self.reporter = nil
            self.apiClient = nil
            self.policyEngine = nil
            self.policyCache = nil
            self.config = nil
            self.currentDeviceId = nil
            self._isInitialized = false
            self._isDetecting = false

            self.log(.info, "[초기화] SDK 정상 종료 완료")
        }
    }

    // MARK: - 내부 메서드 (테스트 용도)

    /// SDK 내부 상태를 완전히 초기화한다.
    internal func reset() {
        DispatchQueue.main.async {
            self.detectionTimer?.invalidate()
            self.detectionTimer = nil
        }
        sdkQueue.sync {
            self.reporter?.shutdown()
            self.reporter = nil
            self.apiClient = nil
            self.policyEngine = nil
            self.policyCache = nil
            self.config = nil
            self.currentDeviceId = nil
            self.delegate = nil
            self._isInitialized = false
            self._isDetecting = false
        }
    }

    // MARK: - 탐지기 등록

    /// 탐지기 9개 전부 등록 (활성화/비활성화는 PolicyEngine 정책으로 제어)
    private func registerDetectors(engine: PolicyEngine, config: GuardConfig) {
        engine.registerDetector(JailbreakDetector())
        engine.registerDetector(SimulatorDetector())
        engine.registerDetector(DebuggerDetector())
        engine.registerDetector(IntegrityDetector())
        engine.registerDetector(HookingDetector())
        engine.registerDetector(SignatureDetector())
        engine.registerDetector(UsbDebugDetector())
        engine.registerDetector(VpnDetector())

        let screenDetector = ScreenCaptureDetector()
        screenDetector.onCaptureStateChanged = { [weak self] isCaptured in
            self?.handleCaptureStateChanged(isCaptured)
        }
        screenDetector.onScreenshotTaken = { [weak self] in
            self?.handleScreenshotTaken()
        }
        engine.registerDetector(screenDetector)

        log(.debug, "탐지기 \(engine.detectorCount)개 등록 완료")
    }

    // MARK: - 탐지 실행 (내부)

    /// 탐지를 1회 실행하고 결과를 delegate에 전달한다.
    private func performDetection() {
        guard self._isInitialized, let engine = self.policyEngine else {
            self.log(.warn, "[탐지] SDK가 초기화되지 않아 탐지를 실행할 수 없습니다.")
            return
        }

        self.log(.debug, "[탐지] 보안 탐지 실행 시작")

        // 정책 엔진을 통해 탐지 실행
        let results = engine.runDetection()

        // 위협 발견 로그 (개별 항목)
        for result in results where result.detected {
            self.log(.warn, "[탐지] 위협 발견: \(result.type.rawValue) (신뢰도=\(result.confidence), 액션=\(result.action.rawValue))")
        }

        // 개별 결과를 delegate에 전달 (메인 스레드)
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }

            for result in results where result.detected {
                self.delegate?.guardSDK(self, didDetect: result)
            }

            // 배치 결과 및 최고 우선순위 액션 전달
            let highestAction = self.determineHighestAction(from: results)
            self.delegate?.guardSDK(self, didCompleteBatch: results, action: highestAction)
        }

        let highestAction = self.determineHighestAction(from: results)
        self.log(.debug, "[탐지] 사이클 완료: \(results.count)건 검사, 최종 액션=\(highestAction.rawValue)")
        self.log(.debug, "[탐지] 보안 탐지 완료: \(results.count)건 검사, \(results.filter { $0.detected }.count)건 탐지")

        // 탐지 결과를 서버에 리포트
        self.reportDetections(results)
    }

    // MARK: - 서버 통신

    /// 서버에서 보안 정책을 수신한다.
    private func fetchPolicyFromServer() {
        guard let client = apiClient else { return }

        let deviceId = UIDevice.current.identifierForVendor?.uuidString ?? UUID().uuidString

        let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0"

        let request = SdkInitRequest(
            platform: "ios",
            appVersion: appVersion,
            deviceId: deviceId,
            osVersion: UIDevice.current.systemVersion,
            deviceModel: Self.machineModel()
        )

        // deviceId를 저장하여 DetectionReporter에서 사용
        self.currentDeviceId = deviceId

        Task { [weak self] in
            guard let self = self else { return }
            let result = await client.initialize(request: request, deviceId: deviceId, appSignature: nil)

            // stop()이 호출되어 이미 정리된 상태면 무시
            guard self._isInitialized else { return }

            switch result {
            case .success(let response):
                let initData = response.data
                self.log(.info, "[서버] 초기화 성공")

                // DetectionReporter 생성 (배치 전송 + 재시도 + 오프라인 저장)
                self.reporter = DetectionReporter(
                    apiClient: client,
                    deviceId: deviceId
                )

                // 서버 정책(PolicyData)을 SDK SecurityPolicy로 변환 및 적용
                let p = initData.policy
                let da = p.detectionActions
                let defaultAction = "LOG"
                let serverPolicy = SecurityPolicy(
                    policyId: "server",
                    jailbreakDetectionEnabled: p.detectRoot,
                    jailbreakDetectionAction: (da["root"] ?? defaultAction).uppercased(),
                    simulatorDetectionEnabled: p.detectEmulator,
                    simulatorDetectionAction: (da["emulator"] ?? defaultAction).uppercased(),
                    debuggerDetectionEnabled: p.detectDebugger,
                    debuggerDetectionAction: (da["debugger"] ?? defaultAction).uppercased(),
                    integrityCheckEnabled: p.detectIntegrity,
                    integrityCheckAction: (da["integrity"] ?? defaultAction).uppercased(),
                    hookingDetectionEnabled: p.detectHooking,
                    hookingDetectionAction: (da["hooking"] ?? defaultAction).uppercased(),
                    signatureVerifyEnabled: p.detectSignature,
                    signatureVerifyAction: (da["signature"] ?? defaultAction).uppercased(),
                    usbDebugDetectionEnabled: p.detectUsbDebug,
                    usbDebugDetectionAction: (da["usb_debug"] ?? defaultAction).uppercased(),
                    vpnDetectionEnabled: p.detectVpn,
                    vpnDetectionAction: (da["vpn"] ?? defaultAction).uppercased(),
                    screenCaptureBlockEnabled: p.detectScreenCapture,
                    screenCaptureBlockAction: (da["screen_capture"] ?? defaultAction).uppercased(),
                    expectedBinaryHash: initData.hashes?.codeHash,
                    expectedSignatureHash: initData.hashes?.signatureHashes?.first
                )
                self.policyEngine?.applyPolicy(serverPolicy)
                self.log(.info, "[정책] 서버 정책 적용 완료: actions=\(da)")

                // 서버에서 동적 시그니처가 포함된 경우 탐지기에 적용 + 캐시 저장
                var policyToCache = serverPolicy
                if let signatures = initData.signatures, !signatures.isEmpty {
                    self.policyEngine?.applySignatures(signatures)
                    policyToCache.detectionSignatures = signatures
                    let rootCount = signatures["root"]?.values.reduce(0) { $0 + $1.count } ?? 0
                    let hookingCount = signatures["hooking"]?.values.reduce(0) { $0 + $1.count } ?? 0
                    self.log(.info, "[정책] 동적 시그니처 적용 완료 (root: \(rootCount)건, hooking: \(hookingCount)건)")
                }
                self.policyCache?.save(policyToCache)

                // 성공 알림 (메인 스레드)
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { return }
                    self.delegate?.guardSDK(self, didUpdateStatus: "서버 정책 수신 완료")
                }

            case .error(_, let message):
                self.log(.warn, "[서버] 초기화 실패: \(message) (오프라인 모드)")
                self.logOfflineFallbackMode()
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { return }
                    self.delegate?.guardSDK(self, didUpdateStatus: "서버 연결 실패: \(message) (오프라인 모드)")
                    self.delegate?.guardSDK(self, didEncounterError: .networkError(NSError(domain: "GuardSDK", code: -1, userInfo: [NSLocalizedDescriptionKey: "서버 초기화 실패: \(message)"])))
                }

            case .networkError(let error):
                self.log(.warn, "[서버] 네트워크 연결 실패: \(error.localizedDescription) (오프라인 모드)")
                self.logOfflineFallbackMode()
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { return }
                    self.delegate?.guardSDK(self, didUpdateStatus: "서버 연결 실패: \(error.localizedDescription) (오프라인 모드)")
                    self.delegate?.guardSDK(self, didEncounterError: .networkError(error))
                }
            }
        }
    }

    /// 오프라인 fallback 모드 안내 로그
    private func logOfflineFallbackMode() {
        if policyCache?.load() != nil {
            log(.info, "[캐시] 오프라인 모드: 캐시된 정책으로 탐지를 계속합니다.")
        } else {
            log(.info, "[캐시] 오프라인 모드: GuardConfig 기반 초기 정책으로 동작합니다.")
        }
    }

    /// 탐지 결과를 서버에 리포트한다.
    private func reportDetections(_ results: [DetectionResult]) {
        let events = results.filter { $0.detected }.map { result in
            DetectionEventModel(
                type: result.type.rawValue.lowercased(),
                details: result.details
            )
        }

        guard !events.isEmpty else { return }

        self.log(.debug, "[리포트] 탐지 리포트 전송: \(events.count)건")

        // DetectionReporter가 있으면 배치 리포터 사용 (재시도 + 오프라인 저장)
        if let reporter = self.reporter {
            Task {
                for event in events {
                    await reporter.addEvent(event)
                }
                // 탐지 결과는 즉시 전송 (배치 대기 없이)
                await reporter.flush()
            }
            return
        }

        // 폴백: 직접 전송 (reporter 미생성 시)
        guard let client = apiClient else { return }

        let deviceId = currentDeviceId ?? UIDevice.current.identifierForVendor?.uuidString ?? UUID().uuidString
        let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String

        Task {
            let result = await client.reportDetections(
                request: DetectionReportRequest(
                    deviceId: deviceId,
                    platform: "ios",
                    appVersion: appVersion,
                    osVersion: UIDevice.current.systemVersion,
                    deviceModel: Self.machineModel(),
                    detections: events
                )
            )
            switch result {
            case .success(let response):
                self.log(.debug, "[리포트] 전송 성공: received=\(response.data.received)")
            case .error(let code, let message):
                self.log(.error, "[리포트] 전송 실패: code=\(code), message=\(message)")
            case .networkError(let error):
                self.log(.error, "[리포트] 네트워크 오류: \(error.localizedDescription)")
            }
        }
    }

    // MARK: - 화면 캡처 이벤트 핸들러

    /// 녹화/미러링 상태 변경 시 호출된다.
    ///
    /// ScreenCaptureDetector의 옵저버가 감지하여 전달한다.
    /// 상태를 서버에 리포트하고 delegate에 알린다.
    ///
    /// - Parameter isCaptured: 현재 녹화/미러링 중 여부
    private func handleCaptureStateChanged(_ isCaptured: Bool) {
        log(.info, "화면 캡처 상태 변경: isCaptured=\(isCaptured)")

        if isCaptured {
            // 녹화 시작 → 즉시 서버에 리포트
            let event = DetectionEventModel(
                type: "screen_capture",
                details: ["event": "recording_started"]
            )
            if let reporter = self.reporter {
                Task { await reporter.addEventImmediate(event) }
            }
        }

        // delegate에 상태 알림
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.delegate?.guardSDK(self, didUpdateStatus: "화면 캡처 상태: \(isCaptured ? "녹화 중" : "정상")")
        }
    }

    /// 스크린샷 촬영 시 호출된다 (사후 감지).
    ///
    /// iOS에서 스크린샷을 차단할 수 없으므로, 촬영 후 서버에 리포트한다.
    private func handleScreenshotTaken() {
        log(.warn, "[화면보호] 스크린샷 촬영 감지 (사후)")

        let event = DetectionEventModel(
            type: "screen_capture",
            details: ["event": "screenshot_taken"]
        )
        if let reporter = self.reporter {
            Task { await reporter.addEventImmediate(event) }
        }

        // 정책 action에 따른 동작 수행 및 delegate 알림
        let result = DetectionResult(
            type: .screenCapture,
            detected: true,
            confidence: 1.0,
            details: ["event": "screenshot_taken"]
        )
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.delegate?.guardSDK(self, didDetect: result)
            self.delegate?.guardSDK(self, didUpdateStatus: "스크린샷 촬영 감지")
        }
    }

    // MARK: - GuardConfig → SecurityPolicy 변환

    /// GuardConfig 설정을 기반으로 초기 SecurityPolicy를 생성한다.
    ///
    /// 서버 연결 전이나 오프라인 모드에서 사용되는 기본 정책이다.
    /// 정책 우선순위: GuardConfig(기본) → 캐시 정책 → 서버 정책(최종)
    ///
    /// - Parameter config: SDK 설정 객체
    /// - Returns: GuardConfig 기반의 SecurityPolicy
    private func createPolicyFromConfig(_ config: GuardConfig) -> SecurityPolicy {
        return SecurityPolicy(
            policyId: "config-default",
            jailbreakDetectionEnabled: config.enableJailbreakDetection,
            jailbreakDetectionAction: "LOG",
            simulatorDetectionEnabled: config.enableSimulatorDetection,
            simulatorDetectionAction: "LOG",
            debuggerDetectionEnabled: config.enableDebuggerDetection,
            debuggerDetectionAction: "LOG",
            integrityCheckEnabled: config.enableIntegrityCheck,
            integrityCheckAction: "LOG",
            hookingDetectionEnabled: config.enableHookingDetection,
            hookingDetectionAction: "LOG",
            signatureVerifyEnabled: config.enableSignatureCheck,
            signatureVerifyAction: "LOG",
            usbDebugDetectionEnabled: config.enableUsbDebugDetection,
            usbDebugDetectionAction: "LOG",
            vpnDetectionEnabled: config.enableVpnDetection,
            vpnDetectionAction: "LOG",
            screenCaptureBlockEnabled: config.enableScreenCaptureBlock,
            screenCaptureBlockAction: "LOG"
        )
    }

    // MARK: - 비공개 헬퍼

    /// 탐지 결과 목록에서 가장 높은 우선순위의 액션을 결정한다.
    /// 우선순위: block > warn > log > none
    private func determineHighestAction(from results: [DetectionResult]) -> DetectAction {
        let detectedResults = results.filter { $0.detected }

        if detectedResults.contains(where: { $0.action == .block }) {
            return .block
        } else if detectedResults.contains(where: { $0.action == .warn }) {
            return .warn
        } else if detectedResults.contains(where: { $0.action == .log }) {
            return .log
        }
        return .log
    }

    /// utsname().machine에서 디바이스 모델명을 반환한다 (예: "iPhone15,2").
    /// UIDevice.current.model은 "iPhone"만 반환하므로 사용하지 않는다.
    static func machineModel() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        return withUnsafePointer(to: &systemInfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                String(cString: $0)
            }
        }
    }

    /// SDK 내부 로그를 출력한다.
    internal func log(_ level: GuardConfig.LogLevel, _ message: String) {
        guard let config = config, level <= config.logLevel else { return }

        let prefix: String
        switch level {
        case .none:
            return
        case .error:
            prefix = "[GuardSDK ERROR]"
        case .warn:
            prefix = "[GuardSDK WARN]"
        case .info:
            prefix = "[GuardSDK INFO]"
        case .debug:
            prefix = "[GuardSDK DEBUG]"
        }

        #if DEBUG
        print("\(prefix) \(message)")
        #endif
    }
}
