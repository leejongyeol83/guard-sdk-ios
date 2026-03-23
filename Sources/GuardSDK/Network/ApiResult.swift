// ApiResult.swift
// GuardSDK - API 호출 결과 래퍼
//
// [CL-17] API 호출의 성공/실패를 타입 안전하게 표현하는 제네릭 열거형

import Foundation

/// API 호출 결과를 나타내는 열거형.
/// - success: 서버 응답 성공 (디코딩된 응답 모델 포함)
/// - error: 서버가 에러 응답을 반환 (HTTP 상태 코드 + 메시지)
/// - networkError: 네트워크 연결 실패 등 통신 오류
enum ApiResult<T> {
    /// 서버 응답 성공 - 디코딩된 응답 모델 포함
    case success(T)

    /// 서버 에러 응답 - HTTP 상태 코드와 에러 메시지
    case error(code: Int, message: String)

    /// 네트워크 오류 - URLSession 통신 실패 등
    case networkError(Error)

    /// 성공 여부 확인
    var isSuccess: Bool {
        if case .success = self { return true }
        return false
    }

    /// 성공 시 값 추출 (실패 시 nil)
    var value: T? {
        if case .success(let val) = self { return val }
        return nil
    }

    /// 에러 코드 추출 (서버 에러인 경우만)
    var errorCode: Int? {
        if case .error(let code, _) = self { return code }
        return nil
    }

    /// 에러 메시지 추출
    var errorMessage: String? {
        switch self {
        case .error(_, let message):
            return message
        case .networkError(let error):
            return error.localizedDescription
        case .success:
            return nil
        }
    }
}
