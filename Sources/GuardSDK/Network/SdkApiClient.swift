// SdkApiClient.swift
// GuardSDK - URLSession 기반 API 클라이언트
//
// [CL-15] 서버 API와 통신하는 HTTP 클라이언트
// 인증 방식: HTTP 헤더 기반
//   - 초기화: X-API-Key + X-Device-Id 헤더
//   - 탐지/하트비트: X-Session-Token 헤더

import Foundation

/// SDK 서버 API 클라이언트
/// URLSession 기반으로 외부 의존성 없이 HTTP 통신을 수행한다.
class SdkApiClient {

    // MARK: - 상수

    /// SDK 버전 (User-Agent 헤더에 포함)
    private static let sdkVersion = "1.0.0"

    /// API 엔드포인트 경로
    private enum Endpoint {
        static let initialize = "/api/sdk/guard/init"
        static let report = "/api/sdk/guard/report"
        // heartbeat는 현재 미사용 (서버 모델에서 제거됨)
    }

    /// HTTP 헤더 키
    private enum HeaderKey {
        static let apiKey = "X-API-Key"
        static let deviceId = "X-Device-Id"
        static let sessionToken = "X-Session-Token"
        static let contentType = "Content-Type"
        static let userAgent = "User-Agent"
    }

    // MARK: - 속성

    /// API 서버 기본 URL
    private let baseUrl: String

    /// SDK API 키
    private let apiKey: String

    /// URLSession 인스턴스 (타임아웃 설정 적용)
    private let session: URLSession

    /// JSON 인코더 (camelCase — 서버 응답 형식 일치)
    private let encoder: JSONEncoder

    /// JSON 디코더 (camelCase — 서버 응답 형식 일치)
    private let decoder: JSONDecoder

    // MARK: - 초기화

    /// SdkApiClient 초기화
    /// - Parameters:
    ///   - baseUrl: API 서버 기본 URL
    ///   - apiKey: SDK API 키
    ///   - config: SDK 설정 (타임아웃 등)
    init(baseUrl: String, apiKey: String, config: SdkConfig) {
        self.baseUrl = baseUrl.hasSuffix("/") ? String(baseUrl.dropLast()) : baseUrl
        self.apiKey = apiKey

        // URLSession 타임아웃 설정
        let sessionConfig = URLSessionConfiguration.default
        sessionConfig.timeoutIntervalForRequest = config.readTimeoutSec
        sessionConfig.timeoutIntervalForResource = config.connectTimeoutSec + config.readTimeoutSec
        sessionConfig.waitsForConnectivity = false
        self.session = URLSession(configuration: sessionConfig)

        // JSON 인코더 설정 (서버가 camelCase를 사용하므로 기본 strategy 유지)
        self.encoder = JSONEncoder()

        // JSON 디코더 설정 (서버가 camelCase를 사용하므로 기본 strategy 유지)
        self.decoder = JSONDecoder()
    }

    // MARK: - 공개 API

    /// SDK 초기화 요청
    /// POST /api/sdk/guard/init
    /// X-API-Key, X-Device-Id 헤더로 인증
    /// - Parameters:
    ///   - request: 초기화 요청 모델
    ///   - deviceId: 디바이스 고유 식별자
    ///   - appSignature: 앱 서명 해시 (선택)
    /// - Returns: 초기화 응답 결과
    func initialize(
        request: SdkInitRequest,
        deviceId: String,
        appSignature: String?
    ) async -> ApiResult<SdkInitResponse> {
        var headers: [String: String] = [
            HeaderKey.apiKey: apiKey,
            HeaderKey.deviceId: deviceId,
        ]

        // 앱 서명 해시가 있으면 헤더에 추가
        if let signature = appSignature {
            headers["X-App-Signature"] = signature
        }

        return await performRequest(
            endpoint: Endpoint.initialize,
            body: request,
            additionalHeaders: headers
        )
    }

    /// 탐지 결과 리포트 요청
    /// POST /api/sdk/guard/report
    /// X-Session-Token 헤더로 인증
    /// - Parameters:
    ///   - request: 탐지 리포트 요청 모델
    ///   - sessionToken: 세션 토큰
    /// - Returns: 리포트 응답 결과
    func reportDetections(
        request: DetectionReportRequest,
        sessionToken: String
    ) async -> ApiResult<DetectionReportResponse> {
        let headers: [String: String] = [
            HeaderKey.sessionToken: sessionToken,
        ]

        return await performRequest(
            endpoint: Endpoint.report,
            body: request,
            additionalHeaders: headers
        )
    }


    // MARK: - 내부 구현

    /// 공통 HTTP POST 요청 수행
    /// - Parameters:
    ///   - endpoint: API 엔드포인트 경로
    ///   - body: 요청 바디 (Encodable)
    ///   - additionalHeaders: 추가 HTTP 헤더
    /// - Returns: 디코딩된 응답 결과
    private func performRequest<RequestBody: Encodable, ResponseBody: Decodable>(
        endpoint: String,
        body: RequestBody,
        additionalHeaders: [String: String]
    ) async -> ApiResult<ResponseBody> {

        // URL 생성
        guard let url = URL(string: baseUrl + endpoint) else {
            return .error(code: -1, message: "잘못된 URL: \(baseUrl + endpoint)")
        }

        // URLRequest 설정
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = "POST"
        urlRequest.setValue("application/json", forHTTPHeaderField: HeaderKey.contentType)
        urlRequest.setValue("GuardSDK-iOS/\(SdkApiClient.sdkVersion)", forHTTPHeaderField: HeaderKey.userAgent)

        // 추가 헤더 설정
        for (key, value) in additionalHeaders {
            urlRequest.setValue(value, forHTTPHeaderField: key)
        }

        // 요청 바디 인코딩
        do {
            urlRequest.httpBody = try encoder.encode(body)
        } catch {
            return .error(code: -1, message: "요청 인코딩 실패: \(error.localizedDescription)")
        }

        // HTTP 요청 실행
        do {
            let (data, response) = try await session.data(for: urlRequest)

            // HTTP 응답 상태 코드 확인
            guard let httpResponse = response as? HTTPURLResponse else {
                return .error(code: -1, message: "잘못된 HTTP 응답")
            }

            let statusCode = httpResponse.statusCode

            // 성공 응답 (2xx)
            if (200...299).contains(statusCode) {
                do {
                    let responseBody = try decoder.decode(ResponseBody.self, from: data)
                    return .success(responseBody)
                } catch {
                    return .error(
                        code: statusCode,
                        message: "응답 디코딩 실패: \(error.localizedDescription)"
                    )
                }
            }

            // 에러 응답 - 서버 에러 메시지 파싱 시도
            if let errorResponse = try? decoder.decode(ApiErrorResponse.self, from: data),
               let errorDetail = errorResponse.error {
                return .error(
                    code: statusCode,
                    message: errorDetail.message ?? "알 수 없는 서버 오류"
                )
            }

            // 에러 메시지 파싱 실패 시 HTTP 상태 코드 기반 메시지
            let errorMessage = String(data: data, encoding: .utf8) ?? "알 수 없는 서버 오류"
            return .error(code: statusCode, message: errorMessage)

        } catch {
            // 네트워크 오류 (타임아웃, 연결 실패 등)
            return .networkError(error)
        }
    }
}
