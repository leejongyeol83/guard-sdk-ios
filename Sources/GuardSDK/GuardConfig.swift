import Foundation

public final class GuardConfig {
    public let apiKey: String
    public let bundleId: String
    public let serverUrl: String
    public let enableJailbreakDetection: Bool
    public let enableSimulatorDetection: Bool
    public let enableDebuggerDetection: Bool
    public let enableIntegrityCheck: Bool
    public let enableSignatureCheck: Bool
    public let enableHookingDetection: Bool
    public let enableUsbDebugDetection: Bool
    public let enableVpnDetection: Bool
    public let enableScreenCaptureBlock: Bool
    public let detectionInterval: Int

    private init(builder: Builder) {
        self.apiKey = builder.apiKey
        self.bundleId = builder.bundleId
        self.serverUrl = builder.serverUrl
        self.enableJailbreakDetection = builder.enableJailbreakDetection
        self.enableSimulatorDetection = builder.enableSimulatorDetection
        self.enableDebuggerDetection = builder.enableDebuggerDetection
        self.enableIntegrityCheck = builder.enableIntegrityCheck
        self.enableSignatureCheck = builder.enableSignatureCheck
        self.enableHookingDetection = builder.enableHookingDetection
        self.enableUsbDebugDetection = builder.enableUsbDebugDetection
        self.enableVpnDetection = builder.enableVpnDetection
        self.enableScreenCaptureBlock = builder.enableScreenCaptureBlock
        self.detectionInterval = builder.detectionInterval
    }

    public final class Builder {
        let apiKey: String
        let bundleId: String
        var serverUrl: String = ""
        var enableJailbreakDetection: Bool = true
        var enableSimulatorDetection: Bool = true
        var enableDebuggerDetection: Bool = true
        var enableIntegrityCheck: Bool = true
        var enableSignatureCheck: Bool = true
        var enableHookingDetection: Bool = true
        var enableUsbDebugDetection: Bool = false
        var enableVpnDetection: Bool = false
        var enableScreenCaptureBlock: Bool = false
        var detectionInterval: Int = 60

        public init(apiKey: String, bundleId: String) {
            self.apiKey = apiKey
            self.bundleId = bundleId
        }

        @discardableResult public func serverUrl(_ url: String) -> Builder { self.serverUrl = url; return self }
        @discardableResult public func enableJailbreakDetection(_ v: Bool) -> Builder { self.enableJailbreakDetection = v; return self }
        @discardableResult public func enableSimulatorDetection(_ v: Bool) -> Builder { self.enableSimulatorDetection = v; return self }
        @discardableResult public func enableDebuggerDetection(_ v: Bool) -> Builder { self.enableDebuggerDetection = v; return self }
        @discardableResult public func enableIntegrityCheck(_ v: Bool) -> Builder { self.enableIntegrityCheck = v; return self }
        @discardableResult public func enableSignatureCheck(_ v: Bool) -> Builder { self.enableSignatureCheck = v; return self }
        @discardableResult public func enableHookingDetection(_ v: Bool) -> Builder { self.enableHookingDetection = v; return self }
        @discardableResult public func enableUsbDebugDetection(_ v: Bool) -> Builder { self.enableUsbDebugDetection = v; return self }
        @discardableResult public func enableVpnDetection(_ v: Bool) -> Builder { self.enableVpnDetection = v; return self }
        @discardableResult public func enableScreenCaptureBlock(_ v: Bool) -> Builder { self.enableScreenCaptureBlock = v; return self }
        @discardableResult public func detectionInterval(_ seconds: Int) -> Builder { self.detectionInterval = seconds; return self }

        public func build() -> GuardConfig { GuardConfig(builder: self) }
    }
}
