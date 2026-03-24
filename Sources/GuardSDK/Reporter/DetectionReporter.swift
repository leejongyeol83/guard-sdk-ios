// DetectionReporter.swift
// GuardSDK - 배치 리포팅 + 재시도 모듈
//
// [CL-18] 탐지 이벤트를 배치 단위로 모아 서버에 전송한다.
// 네트워크 단절 시 UserDefaults에 직렬화하여 오프라인 저장 후 복구 전송한다.
// 지수 백오프 재시도: 1초 -> 2초 -> 4초 (최대 3회)

import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// 탐지 이벤트 배치 리포터
/// 이벤트를 큐에 축적하고 조건 충족 시 서버에 일괄 전송한다.
class DetectionReporter {

    // MARK: - 상수

    /// 즉시 전송 트리거 배치 크기
    static let batchSizeThreshold = 10

    /// 자동 플러시 주기 (5분)
    static let flushInterval: TimeInterval = 300

    /// 최대 재시도 횟수
    static let maxRetry = 3

    /// 지수 백오프 간격 (초): 1 -> 2 -> 4
    static let retryDelays: [TimeInterval] = [1, 2, 4]

    /// 오프라인 이벤트 저장 키 (UserDefaults)
    private static let offlineKey = "guard_offline_events"

    // MARK: - 속성

    /// API 클라이언트 (서버 전송용)
    private let apiClient: SdkApiClient

    /// 디바이스 ID (리포트 요청에 필수)
    private let deviceId: String

    /// 이벤트 큐 (배치 축적)
    private var eventQueue: [DetectionEvent] = []

    /// 큐 접근 동기화를 위한 락
    private let queueLock = NSLock()

    /// 자동 플러시 타이머
    private var flushTimer: Timer?

    /// 종료 여부
    private var isShutdown = false

    // MARK: - 초기화

    /// DetectionReporter 초기화
    /// - Parameters:
    ///   - apiClient: 서버 전송용 API 클라이언트 (API Key 인증)
    ///   - deviceId: 디바이스 고유 식별자
    init(apiClient: SdkApiClient, deviceId: String = UUID().uuidString) {
        self.apiClient = apiClient
        self.deviceId = deviceId
        startFlushTimer()
        recoverOfflineEvents()
    }

    deinit {
        shutdown()
    }

    // MARK: - 공개 API

    /// 탐지 이벤트를 큐에 추가한다.
    /// 큐 크기가 batchSizeThreshold 이상이면 즉시 flush를 수행한다.
    /// - Parameter event: 추가할 탐지 이벤트
    func addEvent(_ event: DetectionEvent) async {
        guard !isShutdown else { return }

        var shouldFlush = false
        var queueSize = 0

        queueLock.lock()
        eventQueue.append(event)
        queueSize = eventQueue.count
        shouldFlush = queueSize >= DetectionReporter.batchSizeThreshold
        queueLock.unlock()

        GuardSDK.shared.log(.debug, "[리포트] 이벤트 추가됨: type=\(event.type), 큐 크기=\(queueSize)")

        // 배치 크기 도달 시 즉시 전송
        if shouldFlush {
            GuardSDK.shared.log(.debug, "[리포트] 큐 크기 임계값 도달 (\(queueSize)), 자동 전송 시작")
            _ = await flush()
        }
    }

    /// 실시간 이벤트를 즉시 서버에 전송한다 (배치 대기 없이).
    /// 스크린샷 감지, 녹화 감지 등 즉각 보고가 필요한 이벤트에 사용한다.
    /// - Parameter event: 즉시 전송할 탐지 이벤트
    func addEventImmediate(_ event: DetectionEvent) async {
        guard !isShutdown else { return }

        queueLock.lock()
        eventQueue.append(event)
        queueLock.unlock()

        _ = await flush()
    }

    /// 큐에 축적된 이벤트를 즉시 서버에 전송한다.
    /// 실패 시 지수 백오프로 최대 3회 재시도한다.
    /// 재시도 실패 시 UserDefaults에 오프라인 저장한다.
    /// - Returns: API 호출 결과 (큐가 비어있으면 nil)
    @discardableResult
    func flush() async -> ApiResult<DetectionReportResponse>? {
        // 큐에서 이벤트 추출 (원자적)
        queueLock.lock()
        guard !eventQueue.isEmpty else {
            queueLock.unlock()
            GuardSDK.shared.log(.debug, "[리포트] 전송할 이벤트 없음")
            return nil
        }
        let eventsToSend = eventQueue
        eventQueue.removeAll()
        queueLock.unlock()

        GuardSDK.shared.log(.debug, "[리포트] 이벤트 전송 시작: \(eventsToSend.count)건")

        // 리포트 요청 생성 (API Key 헤더로 인증)
        let request = DetectionReportRequest(
            deviceId: deviceId,
            platform: "ios",
            appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String,
            osVersion: UIDevice.current.systemVersion,
            deviceModel: DetectionReporter.deviceModel(),
            detections: eventsToSend
        )

        // 지수 백오프 재시도
        for attempt in 0..<DetectionReporter.maxRetry {
            if attempt > 0 {
                let delay = DetectionReporter.retryDelays[
                    min(attempt - 1, DetectionReporter.retryDelays.count - 1)
                ]
                GuardSDK.shared.log(.debug, "[리포트] 재시도 \(attempt)/\(DetectionReporter.maxRetry), \(Int(delay * 1000))ms 대기")
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            }

            let result = await apiClient.reportDetections(request: request)

            switch result {
            case .success(let response):
                GuardSDK.shared.log(.debug, "[리포트] 전송 성공: received=\(response.data.received)")
                return result

            case .error(let code, let message):
                if code == 401 {
                    GuardSDK.shared.log(.error, "[리포트] 인증 에러로 재시도 중단")
                    return result
                }
                GuardSDK.shared.log(.warn, "[리포트] 서버 에러 (시도 \(attempt + 1)/\(DetectionReporter.maxRetry)): code=\(code), message=\(message)")

            case .networkError(let error):
                GuardSDK.shared.log(.warn, "[리포트] 네트워크 에러 (시도 \(attempt + 1)/\(DetectionReporter.maxRetry)): \(error.localizedDescription)")
            }
        }

        // 모든 재시도 실패 - 오프라인 저장
        GuardSDK.shared.log(.error, "[리포트] 모든 재시도 실패, 이벤트를 로컬에 저장")
        saveOfflineEvents(eventsToSend)
        return .networkError(
            NSError(
                domain: "GuardSDK",
                code: -1,
                userInfo: [NSLocalizedDescriptionKey: "모든 재시도 실패, 오프라인 저장됨"]
            )
        )
    }

    /// 오프라인 저장된 이벤트를 복구하여 서버에 전송한다.
    /// 앱 재시작 또는 네트워크 복구 시 호출한다.
    func flushOfflineEvents() async {
        guard !isShutdown else { return }

        // 오프라인 이벤트 로드
        guard let offlineEvents = loadOfflineEvents(), !offlineEvents.isEmpty else {
            return
        }

        // 오프라인 저장소 클리어 (중복 전송 방지)
        clearOfflineEvents()

        GuardSDK.shared.log(.debug, "[리포트] 대기 이벤트 \(offlineEvents.count)건 복구")

        // 리포트 요청 생성 및 전송 (API Key 헤더로 인증)
        let request = DetectionReportRequest(
            deviceId: deviceId,
            platform: "ios",
            appVersion: Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String,
            osVersion: UIDevice.current.systemVersion,
            deviceModel: DetectionReporter.deviceModel(),
            detections: offlineEvents
        )

        let result = await apiClient.reportDetections(request: request)

        // 전송 실패 시 다시 오프라인 저장
        switch result {
        case .success:
            GuardSDK.shared.log(.debug, "[리포트] 오프라인 이벤트 전송 성공")
        case .error, .networkError:
            GuardSDK.shared.log(.warn, "[리포트] 오프라인 이벤트 전송 실패, 다시 저장")
            saveOfflineEvents(offlineEvents)
        }
    }

    /// 리소스 해제 (타이머 중단)
    /// SDK 종료 시 호출한다.
    func shutdown() {
        isShutdown = true
        flushTimer?.invalidate()
        flushTimer = nil
        GuardSDK.shared.log(.debug, "[리포트] DetectionReporter 종료")
    }

    // MARK: - 내부 구현

    /// 자동 플러시 타이머 시작
    private func startFlushTimer() {
        // 메인 스레드에서 Timer 스케줄링
        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.flushTimer = Timer.scheduledTimer(
                withTimeInterval: DetectionReporter.flushInterval,
                repeats: true
            ) { [weak self] _ in
                guard let self = self else { return }
                GuardSDK.shared.log(.debug, "[리포트] 자동 전송 주기 도달 (\(Int(DetectionReporter.flushInterval))s 경과)")
                Task {
                    await self.flush()
                }
            }
        }
    }

    /// 초기화 시 오프라인 이벤트 복구 시도
    private func recoverOfflineEvents() {
        Task {
            await flushOfflineEvents()
        }
    }

    /// 이벤트를 UserDefaults에 오프라인 저장
    /// - Parameter events: 저장할 이벤트 목록
    private func saveOfflineEvents(_ events: [DetectionEvent]) {
        do {
            let encoder = JSONEncoder()
            // 기존 오프라인 이벤트와 병합
            var allEvents = loadOfflineEvents() ?? []
            allEvents.append(contentsOf: events)

            // 최대 100건으로 제한 (메모리 보호)
            if allEvents.count > 100 {
                GuardSDK.shared.log(.warn, "[리포트] 오프라인 이벤트 상한 초과 (\(allEvents.count)건), 최근 100건만 유지")
                allEvents = Array(allEvents.suffix(100))
            }

            let data = try encoder.encode(allEvents)
            UserDefaults.standard.set(data, forKey: DetectionReporter.offlineKey)
            GuardSDK.shared.log(.debug, "[리포트] 대기 이벤트 \(events.count)건 로컬 저장 완료")
        } catch {
            GuardSDK.shared.log(.error, "[리포트] 대기 이벤트 저장 실패: \(error.localizedDescription)")
        }
    }

    /// UserDefaults에서 오프라인 이벤트 로드
    /// - Returns: 저장된 이벤트 목록 (없으면 nil)
    private func loadOfflineEvents() -> [DetectionEvent]? {
        guard let data = UserDefaults.standard.data(forKey: DetectionReporter.offlineKey) else {
            return nil
        }

        do {
            let decoder = JSONDecoder()
            return try decoder.decode([DetectionEvent].self, from: data)
        } catch {
            GuardSDK.shared.log(.error, "[리포트] 대기 이벤트 불러오기 실패: \(error.localizedDescription)")
            clearOfflineEvents()
            return nil
        }
    }

    /// 오프라인 이벤트 저장소 클리어
    private func clearOfflineEvents() {
        UserDefaults.standard.removeObject(forKey: DetectionReporter.offlineKey)
    }

    // MARK: - 디바이스 모델

    /// 디바이스 모델명을 반환한다 (예: "iPhone15,2")
    private static func deviceModel() -> String {
        var systemInfo = utsname()
        uname(&systemInfo)
        return withUnsafePointer(to: &systemInfo.machine) {
            $0.withMemoryRebound(to: CChar.self, capacity: 1) {
                String(cString: $0)
            }
        }
    }
}
