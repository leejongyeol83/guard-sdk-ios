import Foundation

final class ApiClient {
    private let serverUrl: String
    private let apiKey: String
    private let session = URLSession.shared

    init(serverUrl: String, apiKey: String) {
        self.serverUrl = serverUrl.hasSuffix("/") ? String(serverUrl.dropLast()) : serverUrl
        self.apiKey = apiKey
    }

    // MARK: - Init

    func initialize(platform: String, osVersion: String, deviceModel: String, appVersion: String) async throws -> InitData {
        let body: [String: Any] = [
            "platform": platform, "osVersion": osVersion,
            "deviceModel": deviceModel, "appVersion": appVersion,
        ]
        let data = try await post(path: "/api/sdk/guard/init", body: body)
        let response = try JSONDecoder().decode(InitResponse.self, from: data)
        return response.data
    }

    // MARK: - Report

    func report(deviceId: String, platform: String, appVersion: String, osVersion: String, deviceModel: String, detections: [[String: Any]]) async throws -> ReportData {
        let body: [String: Any] = [
            "deviceId": deviceId, "platform": platform,
            "appVersion": appVersion, "osVersion": osVersion,
            "deviceModel": deviceModel, "detections": detections,
        ]
        let data = try await post(path: "/api/sdk/guard/report", body: body)
        let response = try JSONDecoder().decode(ReportResponse.self, from: data)
        return response.data
    }

    // MARK: - Policy

    func fetchPolicy() async throws -> GuardPolicy {
        let data = try await get(path: "/api/sdk/guard/policy")
        let response = try JSONDecoder().decode(PolicyResponse.self, from: data)
        return response.data
    }

    // MARK: - Signatures

    func fetchSignatures(platform: String) async throws -> [GuardSignature] {
        let data = try await get(path: "/api/sdk/guard/signatures?platform=\(platform)")
        let response = try JSONDecoder().decode(SignaturesResponse.self, from: data)
        return response.data
    }

    // MARK: - Code Hash

    func verifyCodeHash(platform: String, codeHash: String) async throws -> Bool {
        let body: [String: Any] = ["platform": platform, "codeHash": codeHash]
        let data = try await post(path: "/api/sdk/guard/code-hash", body: body)
        let response = try JSONDecoder().decode(CodeHashResponse.self, from: data)
        return response.data.valid
    }

    // MARK: - HTTP

    private func get(path: String) async throws -> Data {
        var request = URLRequest(url: URL(string: "\(serverUrl)\(path)")!)
        request.httpMethod = "GET"
        request.setValue(apiKey, forHTTPHeaderField: "X-API-Key")
        let (data, _) = try await session.data(for: request)
        return data
    }

    private func post(path: String, body: [String: Any]) async throws -> Data {
        var request = URLRequest(url: URL(string: "\(serverUrl)\(path)")!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(apiKey, forHTTPHeaderField: "X-API-Key")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, _) = try await session.data(for: request)
        return data
    }
}
