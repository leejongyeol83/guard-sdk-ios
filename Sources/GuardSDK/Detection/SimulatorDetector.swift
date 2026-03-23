import Foundation

enum SimulatorDetector {
    static func detect() -> DetectionResult? {
        #if targetEnvironment(simulator)
        return DetectionResult(type: .simulator, severity: .medium, details: ["method": "compile_flag"])
        #else
        if ProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != nil {
            return DetectionResult(type: .simulator, severity: .medium, details: ["method": "environment"])
        }
        return nil
        #endif
    }
}
