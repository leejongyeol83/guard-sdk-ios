import Foundation

public struct GuardPolicy: Codable {
    public let detectTampering: Bool
    public let detectSignature: Bool
    public let detectDebugger: Bool
    public let detectHooking: Bool
    public let detectRoot: Bool
    public let detectEmulator: Bool
    public let detectUsbDebug: Bool
    public let detectVpn: Bool
    public let detectScreenCapture: Bool
    public let detectionActions: [String: String]
}

public struct GuardSignature: Codable {
    public let category: String
    public let checkMethod: String
    public let value: String
    public let platform: String
}

struct InitResponse: Codable {
    let data: InitData
}

struct InitData: Codable {
    let policy: GuardPolicy
    let hashes: CodeHashes?
    let signatures: [GuardSignature]
}

struct CodeHashes: Codable {
    let iosCodeHash: String?
    let androidCodeHash: String?
}

struct PolicyResponse: Codable {
    let data: GuardPolicy
}

struct SignaturesResponse: Codable {
    let data: [GuardSignature]
}

struct CodeHashResponse: Codable {
    let data: CodeHashResult
}

struct CodeHashResult: Codable {
    let valid: Bool
}

struct ReportResponse: Codable {
    let data: ReportData
}

struct ReportData: Codable {
    let received: Int
    let actions: [String: String]
}
