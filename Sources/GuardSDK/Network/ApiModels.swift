// ApiModels.swift
// GuardSDK - 서버 API 요청/응답 모델
//
// app-manager 서버 응답 형식에 맞춤 (camelCase JSON)

import Foundation

// MARK: - SDK 초기화 요청

/// POST /api/sdk/guard/init 요청 바디
struct SdkInitRequest: Codable {
    let platform: String
    let appVersion: String
    let deviceId: String
    let osVersion: String?
    let deviceModel: String?
}

// MARK: - SDK 초기화 응답

/// { data: { policy, hashes, signatures } }
struct SdkInitResponse: Codable {
    let data: SdkInitData
}

struct SdkInitData: Codable {
    let policy: PolicyData
    let hashes: HashesData?
    let signatures: [String: [String: [String]]]?
}

/// 보안 정책 — 서버 응답 필드명 그대로 (camelCase)
struct PolicyData: Codable {
    let detectIntegrity: Bool
    let detectSignature: Bool
    let detectDebugger: Bool
    let detectHooking: Bool
    let detectRoot: Bool
    let detectEmulator: Bool
    let detectUsbDebug: Bool
    let detectVpn: Bool
    let detectScreenCapture: Bool
    let detectionActions: [String: String]

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        detectIntegrity = try container.decodeIfPresent(Bool.self, forKey: .detectIntegrity) ?? false
        detectSignature = try container.decodeIfPresent(Bool.self, forKey: .detectSignature) ?? false
        detectDebugger = try container.decodeIfPresent(Bool.self, forKey: .detectDebugger) ?? false
        detectHooking = try container.decodeIfPresent(Bool.self, forKey: .detectHooking) ?? false
        detectRoot = try container.decodeIfPresent(Bool.self, forKey: .detectRoot) ?? false
        detectEmulator = try container.decodeIfPresent(Bool.self, forKey: .detectEmulator) ?? false
        detectUsbDebug = try container.decodeIfPresent(Bool.self, forKey: .detectUsbDebug) ?? false
        detectVpn = try container.decodeIfPresent(Bool.self, forKey: .detectVpn) ?? false
        detectScreenCapture = try container.decodeIfPresent(Bool.self, forKey: .detectScreenCapture) ?? false
        detectionActions = try container.decodeIfPresent([String: String].self, forKey: .detectionActions) ?? [:]
    }
}

/// 해시 정보
struct HashesData: Codable {
    let codeHash: String?
    let signatureHashes: [String]?
}

/// 시그니처 항목
public struct SignatureData: Codable {
    public let category: String
    public let checkMethod: String
    public let value: String
    public let platform: String
}

// MARK: - 내부 시그니처 항목 (탐지기 전달용)

/// 탐지기에 전달하기 위한 시그니처 항목.
/// 서버 응답의 SignatureData를 탐지기가 사용하는 형태로 변환할 때 사용한다.
struct SignatureItem {
    let type: String
    let value: String
}

// MARK: - 탐지 리포트 요청

/// POST /api/sdk/guard/report 요청 바디
struct DetectionReportRequest: Codable {
    let deviceId: String
    let platform: String
    let appVersion: String?
    let osVersion: String?
    let deviceModel: String?
    let detections: [DetectionEventModel]
}

/// 개별 탐지 이벤트
struct DetectionEventModel: Codable {
    let type: String
    let details: [String: String]?

    init(type: String, details: [String: String]? = nil) {
        self.type = type
        self.details = details
    }
}

/// DetectionReporter에서 사용하는 타입 별칭
typealias DetectionEvent = DetectionEventModel

// MARK: - 탐지 리포트 응답

/// { data: { received, actions } }
struct DetectionReportResponse: Codable {
    let data: ReportResultData
}

struct ReportResultData: Codable {
    let received: Int
    let actions: [String: String]?
}

// MARK: - 정책 조회 응답

/// GET /api/sdk/guard/policy → { data: PolicyData }
struct PolicyQueryResponse: Codable {
    let data: PolicyData
}

// MARK: - 시그니처 조회 응답

/// GET /api/sdk/guard/signatures → { data: [SignatureData] }
struct SignaturesQueryResponse: Codable {
    let data: [SignatureData]
}

// MARK: - 코드 해시 검증 응답

/// POST /api/sdk/guard/code-hash → { data: { valid } }
struct CodeHashResponse: Codable {
    let data: CodeHashResult
}

struct CodeHashResult: Codable {
    let valid: Bool
}

// MARK: - API 에러 응답

/// { error: { code, message } }
struct ApiErrorResponse: Codable {
    let error: ApiErrorDetail?
}

struct ApiErrorDetail: Codable {
    let code: String?
    let message: String?
}
