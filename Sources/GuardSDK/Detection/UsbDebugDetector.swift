import Foundation

enum UsbDebugDetector {
    static func detect() -> DetectionResult? {
        // iOS에서 USB 디버깅은 디버거 감지와 유사
        // 개발자 모드 활성화 확인
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)

        if result == 0 && (info.kp_proc.p_flag & P_TRACED) != 0 {
            return DetectionResult(type: .usbDebug, severity: .medium, details: ["method": "debugger_attached"])
        }

        return nil
    }
}
