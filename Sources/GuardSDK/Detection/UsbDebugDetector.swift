// UsbDebugDetector.swift
// Anti-Mobile Service iOS SDK - USB 디버그 탐지기
//
// USB 디버깅 연결 환경을 탐지한다.
// iOS에서는 직접적인 USB 디버깅 탐지 API가 제한적이므로,
// 간접 지표를 활용하여 디버그 연결 환경을 추론한다.
//
// 탐지 기법:
// 1. sysctl P_TRACED - 프로세스 추적 상태 확인
// 2. Xcode 환경 변수 - 디버그 환경에서 주입되는 환경 변수 확인
// 3. lockdownd 포트 - iOS lockdownd 서비스 포트 확인

import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// USB 디버깅 연결 환경 탐지기.
///
/// sysctl, 환경 변수, lockdownd 포트 등 간접 지표를 사용하여
/// USB를 통한 디버깅 연결 상태를 추론한다.
///
/// 탐지 판정: sysctl traced AND Xcode 환경변수 → detected=true
class UsbDebugDetector: Detector {

    let type: DetectionType = .usbDebug

    func detect() -> DetectionResult {
        var details: [String: String] = [:]
        var score: Float = 0.0
        let totalChecks: Float = 3

        // 검사 1: sysctl로 프로세스 추적(traced) 상태 확인
        let isTraced = checkSysctlTraced()
        if isTraced {
            score += 1.0
            details["sysctl_traced"] = "프로세스가 추적(traced) 상태임"
        }

        // 검사 2: Xcode 디버그 환경 변수 확인
        let xcodeEnv = checkXcodeEnvironment()
        if xcodeEnv {
            score += 1.0
            details["xcode_env"] = "Xcode 디버그 환경 변수 감지"
        }

        // 검사 3: lockdownd 서비스 포트 확인
        let lockdownd = checkLockdownPort()
        if lockdownd {
            score += 1.0
            details["lockdownd_port"] = "lockdownd 서비스 포트 감지"
        }

        let confidence = min(max(score / totalChecks, 0.0), 1.0)
        // sysctl + Xcode 환경 모두 감지되어야 탐지로 판정 (오탐 방지)
        let detected = isTraced && xcodeEnv

        return DetectionResult(
            type: .usbDebug,
            detected: detected,
            confidence: confidence,
            details: details
        )
    }

    func isAvailable() -> Bool {
        return true
    }

    // MARK: - 검사 메서드

    /// sysctl을 사용하여 현재 프로세스가 추적(traced) 상태인지 확인한다.
    ///
    /// 디버거가 연결되면 커널이 P_TRACED 플래그를 설정한다.
    /// Xcode에서 USB로 디버그 실행 시 이 플래그가 활성화된다.
    ///
    /// - Returns: 프로세스가 추적 중인지 여부
    private func checkSysctlTraced() -> Bool {
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]

        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)
        guard result == 0 else { return false }

        let flags = info.kp_proc.p_flag
        return (flags & P_TRACED) != 0
    }

    /// Xcode 디버그 환경에서 주입되는 환경 변수를 확인한다.
    ///
    /// Xcode에서 앱을 실행하면 다양한 디버그 환경 변수가 설정된다.
    /// 이 변수들이 존재하면 USB 디버그 연결 환경으로 추론한다.
    ///
    /// - Returns: Xcode 디버그 환경 여부
    private func checkXcodeEnvironment() -> Bool {
        let env = ProcessInfo.processInfo.environment

        // Xcode에서 실행 시 설정되는 환경 변수들
        let xcodeIndicators = [
            "DYLD_INSERT_LIBRARIES",
            "__XCODE_BUILT_PRODUCTS_DIR_PATHS",
            "__XPC_DYLD_LIBRARY_PATH",
            "XCODE_DBG_XPC_EXCLUSIONS"
        ]

        for indicator in xcodeIndicators {
            if env[indicator] != nil {
                return true
            }
        }

        return false
    }

    /// iOS lockdownd 서비스 포트(62078)에 연결을 시도하여
    /// USB 통신 서비스가 활성화되어 있는지 확인한다.
    ///
    /// lockdownd는 iOS가 USB로 연결된 컴퓨터와 통신할 때 사용하는 서비스이다.
    /// 샌드박스 제한으로 실패할 수 있으므로 보조 지표로만 사용한다.
    ///
    /// - Returns: lockdownd 포트 접근 가능 여부
    private func checkLockdownPort() -> Bool {
        let port: UInt16 = 62078
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")

        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { return false }
        defer { close(sock) }

        // 비블로킹 연결 시도 (100ms 타임아웃)
        var flags = fcntl(sock, F_GETFL, 0)
        flags |= O_NONBLOCK
        fcntl(sock, F_SETFL, flags)

        let connectResult = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockPtr in
                connect(sock, sockPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        if connectResult == 0 {
            return true
        }

        // EINPROGRESS이면 연결 중 → select로 대기
        if errno == EINPROGRESS {
            var writeSet = fd_set()
            // fd_set을 0으로 초기화 (C 매크로 FD_ZERO 대체)
            memset(&writeSet, 0, MemoryLayout<fd_set>.size)

            // FD_SET 대체: 해당 fd 비트를 설정
            let fd = sock
            withUnsafeMutablePointer(to: &writeSet) { ptr in
                let rawPtr = UnsafeMutableRawPointer(ptr)
                let base = rawPtr.assumingMemoryBound(to: Int32.self)
                base[Int(fd / 32)] |= Int32(1 << (fd % 32))
            }

            var timeout = timeval(tv_sec: 0, tv_usec: 100_000) // 100ms
            let selectResult = select(sock + 1, nil, &writeSet, nil, &timeout)
            return selectResult > 0
        }

        return false
    }
}
