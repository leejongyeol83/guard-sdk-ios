# Guard SDK for iOS

통합 플랫폼(App Manager)의 모바일 보안 탐지 SDK.
탈옥, 시뮬레이터, 디버거, 무결성, 서명, 후킹, USB 디버그, VPN, 화면 캡처 등 9종 보안 위협을 탐지합니다.

## Installation (SPM)

Xcode → File → Add Package Dependencies:

```
https://github.com/leejongyeol83/guard-sdk-ios.git
```

Dependency Rule: **Up to Next Major Version — 1.0.0**

## Quick Start

```swift
import GuardSDK

// 1. Config 생성 (apiKey + serverUrl 필수, bundleId는 자동 감지)
let config = GuardConfig.Builder(apiKey: "pk_your_api_key", serverUrl: "https://your-platform.com")
    .enableJailbreakDetection(true)
    .enableSimulatorDetection(true)
    .enableDebuggerDetection(true)
    .enableIntegrityCheck(true)
    .enableSignatureCheck(true)
    .enableHookingDetection(true)
    .enableUsbDebugDetection(true)
    .enableVpnDetection(true)
    .enableScreenCaptureBlock(true)
    .detectionInterval(60) // 60초
    .logLevel(.debug) // .none, .error, .warn, .info, .debug
    .build()

// 2. 초기화 + 콜백
GuardSDK.shared.initialize(config: config, callback: self)

// 3-A. 주기적 탐지 (initialize 직후 호출 가능, 서버 정책 도착 시 자동 반영)
GuardSDK.shared.startDetection()

// 3-B. 또는 1회 탐지
// GuardSDK.shared.runDetection()

// 4. 콜백
extension ViewController: GuardCallback {
    func onReady(policySource: PolicySource) {
        // 서버 정책 적용 완료 (또는 캐시/기본 정책 폴백)
        // policySource: .server, .cached, .config
    }

    func onDetection(result: DetectionResult) {
        switch result.action {
        case .block:
            // 앱 종료 또는 기능 제한
            break
        case .warn:
            // 사용자에게 경고 표시
            break
        case .log:
            // 로깅만
            break
        case .none:
            // 무시
            break
        }
    }

    func onError(error: SdkError) {
        // 에러 처리
    }
}
```

### 초기화 2단계

1. **Phase 1 (로컬 초기화)**: `initialize()` 호출 → `isInitialized = true`. 탐지기 등록, 캐시 정책 적용. `startDetection()` 호출 가능.
2. **Phase 2 (서버 정책)**: 서버에서 정책 수신 완료 → `isReady = true`. `onReady()` 콜백 호출. 서버 실패 시에도 캐시/기본 정책으로 폴백하여 `onReady()` 호출.

## API

| Method | Description |
|--------|-------------|
| `GuardSDK.shared.initialize(config:callback:)` | SDK 초기화 + 서버 정책 수신 |
| `GuardSDK.shared.startDetection()` | 주기적 탐지 시작 |
| `GuardSDK.shared.stopDetection()` | 탐지 중지 |
| `GuardSDK.shared.runDetection()` | 수동 1회 탐지 |
| `GuardSDK.shared.stop()` | SDK 종료 및 리소스 해제 |
| `GuardSDK.shared.isInitialized` | 로컬 초기화 완료 여부 |
| `GuardSDK.shared.isReady` | 서버 정책 적용 완료 여부 |
| `GuardSDK.shared.policySource` | 현재 적용된 정책 출처 (.config/.cached/.server) |
| `GuardSDK.shared.isDetecting` | 탐지 실행 중 여부 |

## Detection Types (9종)

| Type | Description |
|------|-------------|
| root | 탈옥 탐지 (Cydia, Sileo, 파일 경로, URL 스킴, fork/dyld/symlink) |
| emulator | 시뮬레이터 탐지 (컴파일 플래그, 환경 변수, 아키텍처) |
| debugger | 디버거 연결 탐지 (sysctl P_TRACED, ptrace, exception ports) |
| integrity | 바이너리 무결성 검증 (코드 서명, 암호화 상태) |
| signature | 코드 서명 검증 (Team ID 기반 재서명 탐지) |
| hooking | 후킹 프레임워크 탐지 (Frida, Cycript, MobileSubstrate, fishhook, dyld 이미지) |
| usb_debug | USB 디버그 탐지 (sysctl, Xcode 환경, lockdownd) |
| vpn | VPN 연결 탐지 (utun/ppp/ipsec 인터페이스) |
| screen_capture | 화면 캡처/녹화 탐지 (UIScreen.isCaptured, 스크린샷 알림) |

## Requirements

- iOS 15.0+
- Swift 5.9+
- `X-API-Key`: App Manager에서 발급받은 API Key

## License

Private - API Key 없이는 동작하지 않습니다.
