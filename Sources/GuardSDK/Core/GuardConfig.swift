// GuardConfig.swift
// Guard SDK - SDK 초기화 설정
//
// SDK를 초기화할 때 필요한 모든 설정 값을 담는 구조체.
// Builder 패턴을 통해 편리하게 설정할 수 있다.

import Foundation

// MARK: - SDK 설정 구조체

/// SDK 초기화에 필요한 설정 정보.
///
/// 직접 생성하지 않고, Builder를 통해 생성하는 것을 권장한다.
///
/// 사용 예시:
/// ```swift
/// let config = GuardConfig.Builder(apiKey: "your-api-key", serverUrl: "https://your-server.com")
///     .logLevel(.debug)
///     .build()
/// ```
public struct GuardConfig {

    /// SDK API 키 (필수, 서버에서 발급)
    public let apiKey: String

    /// API 서버 URL (기본: 프로덕션 서버)
    public let serverUrl: String

    /// HTTP 연결 타임아웃 (초, 기본: 10초)
    public let connectTimeoutSec: TimeInterval

    /// HTTP 읽기 타임아웃 (초, 기본: 15초)
    public let readTimeoutSec: TimeInterval

    /// 탐지 주기 (초, 기본: 60, 최소: 10)
    /// 서버 정책에 의해 덮어쓰일 수 있다.
    public let detectionInterval: TimeInterval

    /// 탈옥 탐지 활성화 (기본: false, 서버 정책이 최우선)
    public let enableJailbreakDetection: Bool

    /// 시뮬레이터 탐지 활성화 (기본: false, 서버 정책이 최우선)
    public let enableSimulatorDetection: Bool

    /// 디버거 탐지 활성화 (기본: false, 서버 정책이 최우선)
    public let enableDebuggerDetection: Bool

    /// 앱 무결성 검증 활성화 (기본: false, 서버 정책이 최우선)
    public let enableIntegrityCheck: Bool

    /// 후킹 프레임워크 탐지 활성화 (기본: false, 서버 정책이 최우선)
    public let enableHookingDetection: Bool

    /// 코드 서명 검증 활성화 (기본: false, 서버 정책이 최우선)
    public let enableSignatureCheck: Bool

    /// USB 디버그 탐지 활성화 (기본: false, 서버 정책이 최우선)
    public let enableUsbDebugDetection: Bool

    /// VPN 탐지 활성화 (기본: false, 서버 정책이 최우선)
    public let enableVpnDetection: Bool

    /// 화면 캡처 차단 활성화 (기본: false, 서버 정책이 최우선)
    public let enableScreenCaptureBlock: Bool

    /// SDK 내부 로그 레벨 (기본: .warn)
    public let logLevel: LogLevel

    // MARK: - 로그 레벨

    /// SDK 내부 로그의 출력 레벨을 정의한다.
    /// rawValue가 높을수록 더 상세한 로그가 출력된다.
    public enum LogLevel: Int, Comparable, Sendable {

        /// 로그 출력 없음
        case none = 0

        /// 오류 메시지만 출력
        case error = 1

        /// 경고 이상 출력
        case warn = 2

        /// 정보 이상 출력
        case info = 3

        /// 모든 로그 출력 (디버그 포함)
        case debug = 4

        public static func < (lhs: LogLevel, rhs: LogLevel) -> Bool {
            lhs.rawValue < rhs.rawValue
        }
    }

    // MARK: - Builder

    /// GuardConfig를 단계적으로 설정하기 위한 빌더 클래스.
    ///
    /// 체이닝 패턴을 지원하며, apiKey는 필수 매개변수이다.
    /// build() 호출 시 precondition으로 필수 값을 검증한다.
    public class Builder {

        // 필수 매개변수
        private let apiKey: String
        private let serverUrl: String
        private var connectTimeoutSec: TimeInterval = 10
        private var readTimeoutSec: TimeInterval = 15
        private var detectionInterval: TimeInterval = 60
        private var enableJailbreakDetection: Bool = false
        private var enableSimulatorDetection: Bool = false
        private var enableDebuggerDetection: Bool = false
        private var enableIntegrityCheck: Bool = false
        private var enableHookingDetection: Bool = false
        private var enableSignatureCheck: Bool = false
        private var enableUsbDebugDetection: Bool = false
        private var enableVpnDetection: Bool = false
        private var enableScreenCaptureBlock: Bool = false
        private var logLevel: LogLevel = .none

        /// 빌더를 초기화한다.
        ///
        /// - Parameters:
        ///   - apiKey: SDK API 키 (필수, 비어있으면 안됨)
        ///   - serverUrl: API 서버 URL (필수)
        public init(apiKey: String, serverUrl: String) {
            self.apiKey = apiKey
            self.serverUrl = serverUrl
        }

        /// HTTP 연결 타임아웃을 설정한다 (초).
        @discardableResult
        public func connectTimeoutSec(_ sec: TimeInterval) -> Builder {
            self.connectTimeoutSec = sec
            return self
        }

        /// HTTP 읽기 타임아웃을 설정한다 (초).
        @discardableResult
        public func readTimeoutSec(_ sec: TimeInterval) -> Builder {
            self.readTimeoutSec = sec
            return self
        }

        /// 탐지 주기를 설정한다 (초, 최소 10초).
        @discardableResult
        public func detectionInterval(_ sec: TimeInterval) -> Builder {
            self.detectionInterval = sec
            return self
        }

        /// 탈옥 탐지를 활성화/비활성화한다.
        @discardableResult
        public func enableJailbreakDetection(_ enable: Bool) -> Builder {
            self.enableJailbreakDetection = enable
            return self
        }

        /// 시뮬레이터 탐지를 활성화/비활성화한다.
        @discardableResult
        public func enableSimulatorDetection(_ enable: Bool) -> Builder {
            self.enableSimulatorDetection = enable
            return self
        }

        /// 디버거 탐지를 활성화/비활성화한다.
        @discardableResult
        public func enableDebuggerDetection(_ enable: Bool) -> Builder {
            self.enableDebuggerDetection = enable
            return self
        }

        /// 앱 무결성 검증을 활성화/비활성화한다.
        @discardableResult
        public func enableIntegrityCheck(_ enable: Bool) -> Builder {
            self.enableIntegrityCheck = enable
            return self
        }

        /// 후킹 탐지를 활성화/비활성화한다.
        @discardableResult
        public func enableHookingDetection(_ enable: Bool) -> Builder {
            self.enableHookingDetection = enable
            return self
        }

        /// 코드 서명 검증을 활성화/비활성화한다.
        @discardableResult
        public func enableSignatureCheck(_ enable: Bool) -> Builder {
            self.enableSignatureCheck = enable
            return self
        }

        /// USB 디버그 탐지를 활성화/비활성화한다.
        @discardableResult
        public func enableUsbDebugDetection(_ enable: Bool) -> Builder {
            self.enableUsbDebugDetection = enable
            return self
        }

        /// VPN 탐지를 활성화/비활성화한다.
        @discardableResult
        public func enableVpnDetection(_ enable: Bool) -> Builder {
            self.enableVpnDetection = enable
            return self
        }

        /// 화면 캡처 차단을 활성화/비활성화한다.
        @discardableResult
        public func enableScreenCaptureBlock(_ enable: Bool) -> Builder {
            self.enableScreenCaptureBlock = enable
            return self
        }

        /// SDK 내부 로그 레벨을 설정한다.
        @discardableResult
        public func logLevel(_ level: LogLevel) -> Builder {
            self.logLevel = level
            return self
        }

        /// 설정된 값으로 GuardConfig를 생성한다.
        ///
        /// precondition으로 필수 값을 검증하며,
        /// 조건을 충족하지 않으면 런타임 오류가 발생한다.
        ///
        /// - Returns: 검증 완료된 GuardConfig 인스턴스
        public func build() -> GuardConfig {
            // 필수 값 검증
            precondition(!apiKey.isEmpty, "API Key는 필수입니다")
            precondition(detectionInterval >= 10, "탐지 주기는 최소 10초 이상이어야 합니다")

            return GuardConfig(
                apiKey: apiKey,
                serverUrl: serverUrl,
                connectTimeoutSec: connectTimeoutSec,
                readTimeoutSec: readTimeoutSec,
                detectionInterval: detectionInterval,
                enableJailbreakDetection: enableJailbreakDetection,
                enableSimulatorDetection: enableSimulatorDetection,
                enableDebuggerDetection: enableDebuggerDetection,
                enableIntegrityCheck: enableIntegrityCheck,
                enableHookingDetection: enableHookingDetection,
                enableSignatureCheck: enableSignatureCheck,
                enableUsbDebugDetection: enableUsbDebugDetection,
                enableVpnDetection: enableVpnDetection,
                enableScreenCaptureBlock: enableScreenCaptureBlock,
                logLevel: logLevel
            )
        }
    }
}
