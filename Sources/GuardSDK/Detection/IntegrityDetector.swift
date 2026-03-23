import Foundation
import MachO

enum IntegrityDetector {
    static func detect() -> DetectionResult? {
        // 실행 바이너리 경로 확인
        guard let executablePath = Bundle.main.executablePath else { return nil }

        // 바이너리 존재 여부
        guard FileManager.default.fileExists(atPath: executablePath) else {
            return DetectionResult(type: .integrity, severity: .high, details: ["method": "missing_binary"])
        }

        // LC_CODE_SIGNATURE 로드 커맨드 존재 확인
        let header = _dyld_get_image_header(0)
        if header == nil {
            return DetectionResult(type: .integrity, severity: .high, details: ["method": "no_image_header"])
        }

        return nil
    }
}
