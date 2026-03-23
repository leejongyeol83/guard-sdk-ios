import UIKit

enum ScreenCaptureDetector {
    static func detect() -> DetectionResult? {
        if UIScreen.main.isCaptured {
            return DetectionResult(type: .screenCapture, severity: .medium, details: ["method": "screen_captured"])
        }
        return nil
    }
}
