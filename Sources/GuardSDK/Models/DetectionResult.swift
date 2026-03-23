import Foundation

public enum DetectionType: String, Codable {
    case jailbreak, simulator, debugger, integrity, signature, hooking, usbDebug, vpn, screenCapture
}

public enum Severity: String, Codable {
    case low, medium, high
}

public enum DetectionAction: String, Codable {
    case block, warn, logOnly = "log_only"
}

public struct DetectionResult {
    public let type: DetectionType
    public let severity: Severity
    public let details: [String: Any]?

    public init(type: DetectionType, severity: Severity, details: [String: Any]? = nil) {
        self.type = type
        self.severity = severity
        self.details = details
    }
}
