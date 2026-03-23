// GuardSDK.swift
// Guard SDK - 공개 API 싱글톤 진입점
//
// 호스트 앱에서 SDK를 초기화하고 보안 탐지를 관리하는 메인 클래스.
// 모든 공개 API는 이 클래스를 통해 접근한다.

import Foundation

/// Guard SDK의 공개 진입점.
/// 싱글톤 패턴으로 앱 전체에서 하나의 인스턴스만 사용한다.
///
/// 사용 예시:
/// ```swift
/// let config = SdkConfig.Builder(apiKey: "your-key", appId: "com.example.app")
///     .baseUrl("https://api.example.com")
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
    private var config: SdkConfig?

    /// 세션 토큰 관리 (Keychain 기반)
    private var session: SdkSession?

    /// 보안 정책 로컬 캐시
    private var policyCache: PolicyCache?

    /// 정책 기반 탐지 실행 엔진
    private var policyEngine: PolicyEngine?

    /// API 클라이언트
    private var apiClient: SdkApiClient?

    /// 하트비트 스케줄러
    private var heartbeatScheduler: HeartbeatScheduler?

    /// 탐지 결과 리포터 (배치 전송 + 재시도 + 오프라인 저장)
    private var reporter: DetectionReporter?

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
    public func initialize(config: SdkConfig, delegate: DetectionDelegate? = nil, completion: ((Bool) -> Void)? = nil) {
        sdkQueue.async { [weak self] in
            guard let self = self else {
                DispatchQueue.main.async { completion?(false) }
                return
            }

            // 이미 초기화된 경우 중복 방지
            guard !self._isInitialized else {
                self.log(.warn, "SDK가 이미 초기화되어 있습니다. stop() 후 다시 호출하세요.")
                DispatchQueue.main.async { completion?(true) }
                return
            }

            self.config = config
            self.delegate = delegate

            // 1. 세션 관리자 초기화
            self.session = SdkSession()

            // 2. 정책 캐시 초기화
            self.policyCache = PolicyCache()

            // 3. 정책 엔진 초기화 + Config 기반 탐지기 자동 등록
            let engine = PolicyEngine()
            self.registerDetectors(engine: engine, config: config)
            self.policyEngine = engine

            // 4. SdkConfig 기반 초기 정책 적용 (오프라인 모드의 기본 정책)
            let initialPolicy = self.createPolicyFromConfig(config)
            engine.applyPolicy(initialPolicy)
            self.log(.info, "SdkConfig 기반 초기 정책 적용 완료")

            // 5. 캐시된 정책이 있으면 덮어쓰기 (SdkConfig보다 우선)
            if let cachedPolicy = self.policyCache?.load() {
                engine.applyPolicy(cachedPolicy)
                self.log(.info, "캐시된 보안 정책을 적용했습니다.")
            }

            // 6. API 클라이언트 초기화
            self.apiClient = SdkApiClient(baseUrl: config.baseUrl, apiKey: config.apiKey, config: config)

            // 7. 하트비트 스케줄러 초기화
            if let client = self.apiClient, let session = self.session {
                self.heartbeatScheduler = HeartbeatScheduler(
                    apiClient: client,
                    session: session
                )
                // 하트비트 정책 업데이트 콜백 연결
                self.heartbeatScheduler?.onPolicyUpdate = { [weak self] newPolicy in
                    guard let self = self else { return }
                    self.policyEngine?.applyPolicy(newPolicy)
                    self.policyCache?.save(newPolicy)
                    self.log(.info, "하트비트에서 정책 업데이트 수신")
                }
            }

            // 8. 초기화 완료 표시
            self._isInitialized = true
            self.log(.info, "SDK 초기화 완료 (apiKey: \(config.apiKey.prefix(8))..., 탐지기: \(engine.detectorCount)개)")

            // 9. 완료 콜백 (메인 스레드)
            DispatchQueue.main.async { completion?(true) }

            // 10. 서버에서 세션 토큰 + 정책 수신 (비동기)
            self.fetchPolicyFromServer()
        }
    }

    /// [하위 호환] start()는 initialize()와 동일하게 동작한다.
    public func start(config: SdkConfig, delegate: DetectionDelegate? = nil, completion: ((Bool) -> Void)? = nil) {
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
                self.log(.warn, "SDK가 초기화되지 않아 탐지를 시작할 수 없습니다.")
                self.delegate?.guardSDK(
                    self,
                    didEncounterError: .initializationFailed("SDK가 초기화되지 않았습니다.")
                )
                return
            }

            guard !self._isDetecting else {
                self.log(.warn, "탐지가 이미 실행 중입니다.")
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
                self.log(.info, "주기적 탐지 시작 (주기: \(interval)초)")

                // 화면 캡처 옵저버 시작
                if let screenDetector = self.policyEngine?.getDetector(for: .screenCapture) as? ScreenCaptureDetector {
                    screenDetector.startObserving()
                    self.log(.debug, "화면 캡처 옵저버 시작")
                }

                // 하트비트 시작
                self.heartbeatScheduler?.start()

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

            // 하트비트 중지
            self.heartbeatScheduler?.stop()

            self.log(.info, "주기적 탐지 중지됨 (SDK 초기화 상태 유지)")
        }
    }

    /// 서버에서 최신 정책을 다시 받아온다.
    ///
    /// SDK를 재초기화하지 않고 정책만 갱신한다.
    /// 대시보드에서 정책을 변경한 후 즉시 반영하고 싶을 때 사용한다.
    public func refreshPolicy() {
        sdkQueue.async { [weak self] in
            guard let self = self else { return }

            guard self._isInitialized else {
                self.log(.warn, "SDK가 초기화되지 않아 정책을 갱신할 수 없습니다.")
                return
            }

            self.log(.info, "정책 갱신 요청")
            self.fetchPolicyFromServer()
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
    /// 탐지 중지 + 하트비트 중지 + 내부 상태 초기화.
    /// 다시 사용하려면 initialize()를 재호출해야 한다.
    public func stop() {
        sdkQueue.async { [weak self] in
            guard let self = self else { return }

            guard self._isInitialized else {
                self.log(.warn, "SDK가 초기화되지 않았습니다.")
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
                self.heartbeatScheduler?.stop()
            }

            // 내부 상태 정리
            self.reporter?.shutdown()
            self.reporter = nil
            self.heartbeatScheduler = nil
            self.apiClient = nil
            self.policyEngine = nil
            self.policyCache = nil
            self.session = nil
            self.config = nil
            self._isInitialized = false
            self._isDetecting = false

            self.log(.info, "SDK가 정상 종료되었습니다.")
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
            self.heartbeatScheduler = nil
            self.apiClient = nil
            self.policyEngine = nil
            self.policyCache = nil
            self.session = nil
            self.config = nil
            self.delegate = nil
            self._isInitialized = false
            self._isDetecting = false
        }
    }

    // MARK: - 탐지기 등록

    /// Config 플래그 기반으로 탐지기를 PolicyEngine에 등록한다.
    private func registerDetectors(engine: PolicyEngine, config: SdkConfig) {
        if config.enableJailbreakDetection {
            engine.registerDetector(JailbreakDetector())
            log(.debug, "탈옥 탐지기 등록")
        }
        if config.enableSimulatorDetection {
            engine.registerDetector(SimulatorDetector())
            log(.debug, "시뮬레이터 탐지기 등록")
        }
        if config.enableDebuggerDetection {
            engine.registerDetector(DebuggerDetector())
            log(.debug, "디버거 탐지기 등록")
        }
        if config.enableIntegrityCheck {
            engine.registerDetector(IntegrityDetector())
            log(.debug, "무결성 탐지기 등록")
        }
        if config.enableHookingDetection {
            engine.registerDetector(HookingDetector())
            log(.debug, "후킹 탐지기 등록")
        }
        if config.enableSignatureCheck {
            engine.registerDetector(SignatureDetector())
            log(.debug, "서명 탐지기 등록")
        }
        if config.enableUsbDebugDetection {
            engine.registerDetector(UsbDebugDetector())
            log(.debug, "USB 디버그 탐지기 등록")
        }
        if config.enableVpnDetection {
            engine.registerDetector(VpnDetector())
            log(.debug, "VPN 탐지기 등록")
        }
        if config.enableScreenCaptureBlock {
            let screenDetector = ScreenCaptureDetector()
            screenDetector.onCaptureStateChanged = { [weak self] isCaptured in
                self?.handleCaptureStateChanged(isCaptured)
            }
            screenDetector.onScreenshotTaken = { [weak self] in
                self?.handleScreenshotTaken()
            }
            engine.registerDetector(screenDetector)
            log(.debug, "화면 캡처 탐지기 등록")
        }
    }

    // MARK: - 탐지 실행 (내부)

    /// 탐지를 1회 실행하고 결과를 delegate에 전달한다.
    private func performDetection() {
        guard self._isInitialized, let engine = self.policyEngine else {
            self.log(.warn, "SDK가 초기화되지 않아 탐지를 실행할 수 없습니다.")
            return
        }

        self.log(.debug, "보안 탐지 실행 시작")

        // 정책 엔진을 통해 탐지 실행
        let results = engine.runDetection()

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

        self.log(.debug, "보안 탐지 완료: \(results.count)건 검사, \(results.filter { $0.detected }.count)건 탐지")

        // 탐지 결과를 서버에 리포트
        self.reportDetections(results)
    }

    // MARK: - 서버 통신

    /// 서버에서 세션 토큰과 보안 정책을 수신한다.
    private func fetchPolicyFromServer() {
        guard let client = apiClient else { return }

        let deviceId = UUID().uuidString

        var systemInfo = utsname()
        uname(&systemInfo)
        let deviceModel = withUnsafePointer(to: &systemInfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                String(cString: $0)
            }
        }

        let request = SdkInitRequest(
            platform: "ios",
            osVersion: ProcessInfo.processInfo.operatingSystemVersionString,
            deviceModel: deviceModel,
            appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "1.0.0",
            sdkVersion: "1.0.0"
        )

        Task { [weak self] in
            guard let self = self else { return }
            let result = await client.initialize(request: request, deviceId: deviceId, appSignature: nil)

            // stop()이 호출되어 이미 정리된 상태면 무시
            guard self._isInitialized else { return }

            switch result {
            case .success(let response):
                _ = self.session?.saveToken(response.sessionToken, ttl: 3600)
                self.log(.info, "서버 초기화 성공 (세션 토큰 수신)")

                // DetectionReporter 생성 (배치 전송 + 재시도 + 오프라인 저장)
                self.reporter = DetectionReporter(apiClient: client, sessionToken: response.sessionToken)

                // 서버 정책을 SDK SecurityPolicy로 변환 및 적용
                let p = response.policy
                let da = p.detectionActions ?? [:]
                let serverPolicy = SecurityPolicy(
                    policyId: "server",
                    jailbreakDetectionEnabled: p.rootDetectionEnabled,
                    jailbreakDetectionAction: (da["root_detection"] ?? p.onDetectAction).uppercased(),
                    simulatorDetectionEnabled: p.emulatorDetectionEnabled,
                    simulatorDetectionAction: (da["emulator_detection"] ?? p.onDetectAction).uppercased(),
                    debuggerDetectionEnabled: p.debuggerDetectionEnabled,
                    debuggerDetectionAction: (da["debugger_detection"] ?? p.onDetectAction).uppercased(),
                    integrityCheckEnabled: p.integrityCheckEnabled,
                    integrityCheckAction: (da["integrity_check"] ?? p.onDetectAction).uppercased(),
                    hookingDetectionEnabled: p.hookingDetectionEnabled,
                    hookingDetectionAction: (da["hooking_detection"] ?? p.onDetectAction).uppercased(),
                    signatureVerifyEnabled: p.signatureVerifyEnabled ?? true,
                    signatureVerifyAction: (da["signature_verify"] ?? p.onDetectAction).uppercased(),
                    usbDebugDetectionEnabled: p.usbDebugDetectionEnabled ?? false,
                    usbDebugDetectionAction: (da["usb_debug_detection"] ?? p.onDetectAction).uppercased(),
                    vpnDetectionEnabled: p.vpnDetectionEnabled ?? false,
                    vpnDetectionAction: (da["vpn_detection"] ?? p.onDetectAction).uppercased(),
                    screenCaptureBlockEnabled: p.screenCaptureBlockEnabled ?? false,
                    screenCaptureBlockAction: (da["screen_capture_block"] ?? p.onDetectAction).uppercased(),
                    expectedBinaryHash: p.expectedApkHash,
                    expectedSignatureHash: p.expectedSignatureHash
                )
                self.policyEngine?.applyPolicy(serverPolicy)
                self.policyCache?.save(serverPolicy)
                self.log(.info, "서버 정책 적용: on_detect=\(p.onDetectAction), actions=\(da)")

                // 서버에서 동적 시그니처가 포함된 경우 탐지기에 적용
                if let signatures = response.signatures {
                    self.policyEngine?.applySignatures(signatures)
                    self.log(.info, "동적 시그니처 적용 완료 (root: \(signatures.root.count)건, hooking: \(signatures.hooking.count)건)")
                }

                // 성공 알림 (메인 스레드)
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { return }
                    self.delegate?.guardSDK(self, didUpdateStatus: "서버 정책 수신 완료 (액션: \(p.onDetectAction))")
                }

            case .error(_, let message):
                self.log(.error, "서버 초기화 실패: \(message)")
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { return }
                    self.delegate?.guardSDK(self, didUpdateStatus: "서버 연결 실패: \(message) (오프라인 모드)")
                    self.delegate?.guardSDK(self, didEncounterError: .networkError(NSError(domain: "GuardSDK", code: -1, userInfo: [NSLocalizedDescriptionKey: "서버 초기화 실패: \(message)"])))
                }

            case .networkError(let error):
                self.log(.error, "네트워크 연결 실패: \(error.localizedDescription)")
                DispatchQueue.main.async { [weak self] in
                    guard let self = self else { return }
                    self.delegate?.guardSDK(self, didUpdateStatus: "서버 연결 실패: \(error.localizedDescription) (오프라인 모드)")
                    self.delegate?.guardSDK(self, didEncounterError: .networkError(error))
                }
            }
        }
    }

    /// 탐지 결과를 서버에 리포트한다.
    private func reportDetections(_ results: [DetectionResult]) {
        let events = results.filter { $0.detected }.map { result in
            DetectionEventModel(
                type: result.type.rawValue.lowercased(),
                timestamp: ISO8601DateFormatter().string(from: Date())
            )
        }

        guard !events.isEmpty else { return }

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
        guard let client = apiClient,
              let sessionToken = session?.getToken() else { return }

        Task {
            _ = await client.reportDetections(
                request: DetectionReportRequest(detections: events),
                sessionToken: sessionToken
            )
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
                severity: "high",
                timestamp: ISO8601DateFormatter().string(from: Date()),
                metadata: ["event": "recording_started"]
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
        log(.warn, "스크린샷 촬영 감지 (사후)")

        let event = DetectionEventModel(
            type: "screen_capture",
            severity: "medium",
            timestamp: ISO8601DateFormatter().string(from: Date()),
            metadata: ["event": "screenshot_taken"]
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

    // MARK: - SdkConfig → SecurityPolicy 변환

    /// SdkConfig 설정을 기반으로 초기 SecurityPolicy를 생성한다.
    ///
    /// 서버 연결 전이나 오프라인 모드에서 사용되는 기본 정책이다.
    /// 정책 우선순위: SdkConfig(기본) → 캐시 정책 → 서버 정책(최종)
    ///
    /// - Parameter config: SDK 설정 객체
    /// - Returns: SdkConfig 기반의 SecurityPolicy
    private func createPolicyFromConfig(_ config: SdkConfig) -> SecurityPolicy {
        return SecurityPolicy(
            policyId: "config-default",
            jailbreakDetectionEnabled: config.enableJailbreakDetection,
            jailbreakDetectionAction: "WARN",
            simulatorDetectionEnabled: config.enableSimulatorDetection,
            simulatorDetectionAction: "WARN",
            debuggerDetectionEnabled: config.enableDebuggerDetection,
            debuggerDetectionAction: "WARN",
            integrityCheckEnabled: config.enableIntegrityCheck,
            integrityCheckAction: "WARN",
            hookingDetectionEnabled: config.enableHookingDetection,
            hookingDetectionAction: "WARN",
            signatureVerifyEnabled: config.enableSignatureCheck,
            signatureVerifyAction: "WARN",
            usbDebugDetectionEnabled: config.enableUsbDebugDetection,
            usbDebugDetectionAction: "WARN",
            vpnDetectionEnabled: config.enableVpnDetection,
            vpnDetectionAction: "WARN",
            screenCaptureBlockEnabled: config.enableScreenCaptureBlock,
            screenCaptureBlockAction: "WARN"
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
        return .none
    }

    /// SDK 내부 로그를 출력한다.
    private func log(_ level: SdkConfig.LogLevel, _ message: String) {
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
