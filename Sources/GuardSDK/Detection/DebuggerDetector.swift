import Foundation

enum DebuggerDetector {
    static func detect() -> DetectionResult? {
        // sysctl P_TRACED 체크
        var info = kinfo_proc()
        var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()]
        let result = sysctl(&mib, UInt32(mib.count), &info, &size, nil, 0)

        if result == 0 && (info.kp_proc.p_flag & P_TRACED) != 0 {
            return DetectionResult(type: .debugger, severity: .high, details: ["method": "sysctl_p_traced"])
        }

        // 부모 프로세스 체크 (Xcode 등)
        if getppid() != 1 {
            return DetectionResult(type: .debugger, severity: .medium, details: ["method": "ppid_check", "ppid": getppid()])
        }

        return nil
    }
}
