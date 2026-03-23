import Foundation

final class DetectionEngine {
    private var policy: GuardPolicy?
    private var signatures: [GuardSignature] = []

    func updatePolicy(_ policy: GuardPolicy, signatures: [GuardSignature]) {
        self.policy = policy
        self.signatures = signatures
    }

    func runAll(config: GuardConfig) -> [DetectionResult] {
        guard let policy = policy else { return [] }
        var results: [DetectionResult] = []

        if policy.detectRoot && config.enableJailbreakDetection {
            let jbSignatures = signatures.filter { $0.category == "root" && ($0.platform == "ios" || $0.platform == "all") }
            if let result = JailbreakDetector.detect(signatures: jbSignatures) { results.append(result) }
        }
        if policy.detectEmulator && config.enableSimulatorDetection {
            if let result = SimulatorDetector.detect() { results.append(result) }
        }
        if policy.detectDebugger && config.enableDebuggerDetection {
            if let result = DebuggerDetector.detect() { results.append(result) }
        }
        if policy.detectTampering && config.enableIntegrityCheck {
            if let result = IntegrityDetector.detect() { results.append(result) }
        }
        if policy.detectSignature && config.enableSignatureCheck {
            if let result = SignatureDetector.detect() { results.append(result) }
        }
        if policy.detectHooking && config.enableHookingDetection {
            let hookSignatures = signatures.filter { $0.category == "hooking" && ($0.platform == "ios" || $0.platform == "all") }
            if let result = HookingDetector.detect(signatures: hookSignatures) { results.append(result) }
        }
        if policy.detectUsbDebug && config.enableUsbDebugDetection {
            if let result = UsbDebugDetector.detect() { results.append(result) }
        }
        if policy.detectVpn && config.enableVpnDetection {
            if let result = VpnDetector.detect() { results.append(result) }
        }
        if policy.detectScreenCapture && config.enableScreenCaptureBlock {
            if let result = ScreenCaptureDetector.detect() { results.append(result) }
        }

        return results
    }
}
