# Guard SDK for iOS

Security detection SDK for the unified platform. (Jailbreak, Tampering, Debugger, etc.)

## Installation (SPM)

Xcode → File → Add Package Dependencies:
```
https://github.com/leejongyeol83/guard-sdk-ios.git
```

## Usage

```swift
let apiKey = "pk_your_api_key"
let serverURL = "https://your-platform.com"

GuardSDK.configure(serverURL: serverURL, apiKey: apiKey) { result in
    // Handle detection result
}
```
