# Guard SDK for iOS

통합 플랫폼(App Manager)의 모바일 보안 탐지 SDK.
탈옥, 시뮬레이터, 디버거, 무결성, 서명, 후킹, USB 디버그, VPN, 화면 캡처 등 9종 보안 위협을 탐지합니다.

## Installation (SPM)

Xcode → File → Add Package Dependencies:

```
https://github.com/leejongyeol83/guard-sdk-ios.git
```

Branch: `main` 또는 태그 `v1.0.0`

## Quick Start

```swift
import GuardSDK

// 1. Config 생성
let config = GuardConfig.Builder(apiKey: "pk_your_api_key", bundleId: "com.am.guard")
    .serverUrl("https://your-platform.com")
    .enableJailbreakDetection(true)
    .enableSimulatorDetection(true)
    .enableDebuggerDetection(true)
    .enableIntegrityCheck(true)
    .enableSignatureCheck(true)
    .enableHookingDetection(true)
    .enableUsbDebugDetection(false)
    .enableVpnDetection(false)
    .enableScreenCaptureBlock(false)
    .detectionInterval(60) // 60초
    .build()

// 2. 초기화
GuardSDK.shared.initialize(config: config, delegate: self) { success in
    if success {
        // 3. 탐지 시작
        GuardSDK.shared.startDetection()
    }
}

// 4. Delegate
extension ViewController: GuardDelegate {
    func guardSDK(_ sdk: GuardSDK, didDetect result: DetectionResult, action: DetectionAction) {
        switch action {
        case .block:
            // 앱 종료 또는 기능 제한
            break
        case .warn:
            // 사용자에게 경고 표시
            break
        case .logOnly:
            // 로깅만
            break
        }
    }

    func guardSDK(_ sdk: GuardSDK, didFailWithError error: Error) {
        // 초기화 실패 처리
    }
}
```

## API

| Method | Description |
|--------|-------------|
| `GuardSDK.shared.initialize(config:delegate:completion:)` | SDK 초기화 (서버에서 정책/시그니처 수신) |
| `GuardSDK.shared.startDetection()` | 주기적 탐지 시작 |
| `GuardSDK.shared.stopDetection()` | 탐지 중지 |
| `GuardSDK.shared.runDetection()` | 수동 1회 탐지 |
| `GuardSDK.shared.refreshPolicy()` | 서버에서 정책 갱신 |
| `GuardSDK.shared.stop()` | SDK 종료 및 리소스 해제 |
| `GuardSDK.shared.isInitialized` | 초기화 완료 여부 |
| `GuardSDK.shared.isDetecting` | 탐지 실행 중 여부 |

## Detection Types (9종)

| Type | Description |
|------|-------------|
| jailbreak | 탈옥 탐지 (Cydia, Sileo, 파일 경로, URL 스킴) |
| simulator | 시뮬레이터 탐지 (컴파일 플래그, 환경 변수) |
| debugger | 디버거 연결 탐지 (sysctl P_TRACED, ppid) |
| integrity | 바이너리 무결성 검증 (__TEXT 해시) |
| signature | 코드 서명 검증 (프로비저닝 프로파일) |
| hooking | 후킹 프레임워크 탐지 (Frida, Cycript, MobileSubstrate, dyld 이미지) |
| usbDebug | USB 디버그 탐지 |
| vpn | VPN 연결 탐지 (utun/ppp/ipsec 인터페이스) |
| screenCapture | 화면 캡처/녹화 탐지 (UIScreen.isCaptured) |

## Requirements

- iOS 15.0+
- Swift 5.9+
- `X-API-Key`: App Manager에서 발급받은 API Key

## License

Private - API Key 없이는 동작하지 않습니다.
