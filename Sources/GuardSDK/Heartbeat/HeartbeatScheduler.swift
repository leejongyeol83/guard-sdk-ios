// HeartbeatScheduler.swift
// GuardSDK - BGTaskScheduler + Timer 이중 전략 하트비트 스케줄러
//
// [CL-19] 포그라운드: Timer 기반 주기 실행
//         백그라운드: BGTaskScheduler 등록 (#if os(iOS) && canImport(BackgroundTasks))
// 하트비트 주기: 기본 15분 (900초)

import Foundation
#if os(iOS) && canImport(BackgroundTasks)
import BackgroundTasks
#endif
#if canImport(UIKit)
import UIKit
#endif

/// 하트비트 스케줄러
/// 포그라운드에서는 Timer, 백그라운드에서는 BGTaskScheduler를 사용하여
/// 주기적으로 서버에 하트비트를 전송한다.
class HeartbeatScheduler {

    // MARK: - 상수

    /// 백그라운드 태스크 식별자
    static let bgTaskIdentifier = "com.guard.sdk.heartbeat"

    /// 기본 하트비트 주기 (15분)
    static let defaultInterval: TimeInterval = 900

    // MARK: - 속성

    /// API 클라이언트 (하트비트 전송용)
    private let apiClient: SdkApiClient

    /// 세션 관리자 (토큰 조회용)
    private let session: SdkSession

    /// 하트비트 주기 (초)
    private var interval: TimeInterval

    /// 포그라운드 타이머
    private var foregroundTimer: Timer?

    /// 실행 중 여부
    private var isRunning = false

    /// 최근 탐지 결과 요약 (하트비트에 포함)
    private var detectionSummary: [String: Bool] = [:]

    /// 정책 업데이트 콜백
    var onPolicyUpdate: ((SecurityPolicy) -> Void)?

    // MARK: - 초기화

    /// HeartbeatScheduler 초기화
    /// - Parameters:
    ///   - apiClient: 서버 전송용 API 클라이언트
    ///   - session: 세션 토큰 관리자
    ///   - interval: 하트비트 주기 (초, 기본 15분)
    init(
        apiClient: SdkApiClient,
        session: SdkSession,
        interval: TimeInterval = HeartbeatScheduler.defaultInterval
    ) {
        self.apiClient = apiClient
        self.session = session
        self.interval = max(interval, 60)  // 최소 1분
    }

    // MARK: - 공개 API

    /// 하트비트 스케줄링 시작
    /// 포그라운드 Timer와 백그라운드 BGTaskScheduler를 모두 등록한다.
    func start() {
        guard !isRunning else { return }
        isRunning = true

        // 포그라운드 Timer 시작
        startForegroundTimer()

        // 백그라운드 태스크 등록
        registerBackgroundTask()

        // 앱 라이프사이클 감지 (포그라운드/백그라운드 전환)
        observeAppLifecycle()
    }

    /// 하트비트 스케줄링 중지
    /// 타이머 및 백그라운드 태스크를 해제한다.
    func stop() {
        isRunning = false

        // 포그라운드 타이머 중지
        foregroundTimer?.invalidate()
        foregroundTimer = nil

        // 백그라운드 태스크 취소
        #if os(iOS) && canImport(BackgroundTasks)
        if #available(iOS 13.0, *) {
            BGTaskScheduler.shared.cancel(taskRequestWithIdentifier: HeartbeatScheduler.bgTaskIdentifier)
        }
        #endif

        // 라이프사이클 옵저버 제거
        #if canImport(UIKit)
        NotificationCenter.default.removeObserver(self)
        #endif
    }

    /// 하트비트 1회 실행
    /// 서버에 하트비트를 전송하고 정책 업데이트를 확인한다.
    func sendHeartbeat() async {
        guard let token = session.getToken(), !session.isExpired() else {
            return
        }

        let request = HeartbeatRequest()

        let result = await apiClient.sendHeartbeat(
            request: request,
            sessionToken: token
        )

        switch result {
        case .success(let response):
            // 세션 상태 확인
            if response.status == "expired" {
                // 세션 만료 시 토큰 클리어
                session.clear()
                return
            }

            // 정책 업데이트 확인
            if response.policyUpdated, let newPolicy = response.policy {
                onPolicyUpdate?(newPolicy)
            }

        case .error, .networkError:
            // 하트비트 실패 시 무시 (다음 주기에 재시도)
            break
        }
    }

    /// 탐지 결과 요약을 업데이트한다.
    /// PolicyEngine에서 탐지 완료 후 호출한다.
    /// - Parameter summary: 탐지 유형별 결과 (예: ["jailbreak": false])
    func updateDetectionSummary(_ summary: [String: Bool]) {
        detectionSummary = summary
    }

    // MARK: - 내부 구현

    /// 포그라운드 Timer 시작
    private func startForegroundTimer() {
        // 메인 스레드에서 기존 타이머 정리 + 새 타이머 생성 (동일 스레드에서 원자적 처리)
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.isRunning else { return }

            // 기존 타이머 정리
            self.foregroundTimer?.invalidate()

            self.foregroundTimer = Timer.scheduledTimer(
                withTimeInterval: self.interval,
                repeats: true
            ) { [weak self] _ in
                guard let self = self else { return }
                Task {
                    await self.sendHeartbeat()
                }
            }
        }
    }

    /// BGTaskScheduler에 백그라운드 태스크 등록
    private func registerBackgroundTask() {
        #if os(iOS) && canImport(BackgroundTasks)
        if #available(iOS 13.0, *) {
            // 백그라운드 태스크 핸들러 등록
            BGTaskScheduler.shared.register(
                forTaskWithIdentifier: HeartbeatScheduler.bgTaskIdentifier,
                using: nil
            ) { [weak self] task in
                guard let refreshTask = task as? BGAppRefreshTask else {
                    task.setTaskCompleted(success: false)
                    return
                }
                self?.handleBackgroundTask(refreshTask)
            }

            // 백그라운드 태스크 요청 스케줄링
            scheduleBackgroundTask()
        }
        #endif
    }

    /// 백그라운드 태스크 요청 스케줄링
    #if os(iOS) && canImport(BackgroundTasks)
    @available(iOS 13.0, *)
    private func scheduleBackgroundTask() {
        let request = BGAppRefreshTaskRequest(identifier: HeartbeatScheduler.bgTaskIdentifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: interval)

        do {
            try BGTaskScheduler.shared.submit(request)
        } catch {
            // 백그라운드 태스크 스케줄링 실패 (시뮬레이터 등에서 발생 가능)
        }
    }
    #endif

    /// 백그라운드 태스크 핸들러
    #if os(iOS) && canImport(BackgroundTasks)
    @available(iOS 13.0, *)
    private func handleBackgroundTask(_ task: BGAppRefreshTask) {
        // 다음 태스크 스케줄링
        scheduleBackgroundTask()

        // 태스크 만료 핸들러
        task.expirationHandler = {
            task.setTaskCompleted(success: false)
        }

        // 하트비트 전송
        Task {
            await sendHeartbeat()
            task.setTaskCompleted(success: true)
        }
    }
    #endif

    /// 앱 라이프사이클 옵저버 등록
    /// 포그라운드 복귀 시 타이머 재시작, 백그라운드 진입 시 BGTask 스케줄링
    private func observeAppLifecycle() {
        #if canImport(UIKit)
        NotificationCenter.default.addObserver(
            self,
            selector: #selector(appDidBecomeActive),
            name: UIApplication.didBecomeActiveNotification,
            object: nil
        )

        NotificationCenter.default.addObserver(
            self,
            selector: #selector(appDidEnterBackground),
            name: UIApplication.didEnterBackgroundNotification,
            object: nil
        )
        #endif
    }

    /// 앱이 포그라운드로 복귀했을 때
    @objc private func appDidBecomeActive() {
        guard isRunning else { return }
        startForegroundTimer()

        // 복귀 즉시 하트비트 1회 전송
        Task {
            await sendHeartbeat()
        }
    }

    /// 앱이 백그라운드로 진입했을 때
    @objc private func appDidEnterBackground() {
        // 포그라운드 타이머 중지 (백그라운드에서 Timer 동작 불가)
        foregroundTimer?.invalidate()
        foregroundTimer = nil

        // 백그라운드 태스크 스케줄링
        #if os(iOS) && canImport(BackgroundTasks)
        if #available(iOS 13.0, *) {
            scheduleBackgroundTask()
        }
        #endif
    }
}
