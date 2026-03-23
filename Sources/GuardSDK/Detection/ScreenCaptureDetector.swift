// ScreenCaptureDetector.swift
// Anti-Mobile Service iOS SDK - 화면 캡처 탐지기
//
// iOS에서는 화면 캡처를 완전히 차단할 수 없으므로,
// 녹화/미러링 상태를 감지하고 스크린샷 촬영을 사후 감지한다.
//
// 탐지 기법:
// 1. UIScreen.main.isCaptured - 화면 녹화/AirPlay 미러링 감지
// 2. NotificationCenter 옵저버 - 실시간 상태 변경 알림
//    - capturedDidChangeNotification: 녹화 상태 변경
//    - userDidTakeScreenshotNotification: 스크린샷 촬영 (사후 감지)

import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// 화면 캡처 탐지기.
///
/// iOS에서는 화면 캡처를 OS 수준에서 차단할 수 없다.
/// 대신 `UIScreen.main.isCaptured`로 녹화/미러링을 감지하고,
/// `NotificationCenter` 옵저버로 실시간 이벤트를 전달한다.
///
/// 탐지 판정:
/// - detected=true: 현재 화면 녹화/미러링 중
/// - detected=false: 녹화/미러링 없음
///
/// 스크린샷은 `detect()` 시점에는 감지 불가하며,
/// `onScreenshotTaken` 콜백으로 사후 이벤트만 전달된다.
class ScreenCaptureDetector: Detector {

    let type: DetectionType = .screenCapture

    /// 녹화 상태 변경 콜백 (SDK에서 설정)
    var onCaptureStateChanged: ((Bool) -> Void)?

    /// 스크린샷 촬영 콜백 (SDK에서 설정)
    var onScreenshotTaken: (() -> Void)?

    /// 옵저버 등록 상태
    private var isObserving = false

    /// 옵저버 토큰 (해제용)
    private var captureObserver: NSObjectProtocol?
    private var screenshotObserver: NSObjectProtocol?

    func detect() -> DetectionResult {
        var details: [String: String] = [:]

        // 현재 화면 녹화/미러링 상태 확인
        let isCaptured = checkScreenCaptured()
        if isCaptured {
            details["screen_captured"] = "화면 녹화/미러링 감지"
        } else {
            details["screen_captured"] = "화면 녹화 없음"
        }

        let detected = isCaptured
        let confidence: Float = isCaptured ? 1.0 : 0.0

        return DetectionResult(
            type: .screenCapture,
            detected: detected,
            confidence: confidence,
            details: details
        )
    }

    func isAvailable() -> Bool {
        return true
    }

    // MARK: - 옵저버 관리

    /// 화면 캡처 이벤트 옵저버를 등록한다.
    ///
    /// SDK의 startDetection() 시 호출된다.
    /// 녹화 상태 변경과 스크린샷 촬영을 실시간으로 감지한다.
    func startObserving() {
        guard !isObserving else { return }
        isObserving = true

        #if canImport(UIKit)
        // 녹화 상태 변경 옵저버
        captureObserver = NotificationCenter.default.addObserver(
            forName: UIScreen.capturedDidChangeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            let isCaptured = UIScreen.main.isCaptured
            self?.onCaptureStateChanged?(isCaptured)
        }

        // 스크린샷 촬영 옵저버
        screenshotObserver = NotificationCenter.default.addObserver(
            forName: UIApplication.userDidTakeScreenshotNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            self?.onScreenshotTaken?()
        }
        #endif
    }

    /// 화면 캡처 이벤트 옵저버를 해제한다.
    ///
    /// SDK의 stopDetection() 시 호출된다.
    func stopObserving() {
        guard isObserving else { return }
        isObserving = false
        if let observer = captureObserver {
            NotificationCenter.default.removeObserver(observer)
            captureObserver = nil
        }
        if let observer = screenshotObserver {
            NotificationCenter.default.removeObserver(observer)
            screenshotObserver = nil
        }
    }

    deinit {
        stopObserving()
    }

    // MARK: - 검사 메서드

    /// UIScreen.main.isCaptured를 확인하여 녹화/미러링 상태를 반환한다.
    ///
    /// isCaptured가 true인 경우:
    /// - 화면 녹화 중 (Control Center에서 시작)
    /// - AirPlay 미러링 중
    /// - QuickTime 연결 중
    ///
    /// - Returns: 화면 녹화/미러링 여부
    private func checkScreenCaptured() -> Bool {
        #if canImport(UIKit)
        return UIScreen.main.isCaptured
        #else
        return false
        #endif
    }
}
