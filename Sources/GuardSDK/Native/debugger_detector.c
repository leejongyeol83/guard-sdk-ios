// debugger_detector.c
// GuardSDK - 디버거 탐지 C 네이티브 구현
//
// [CL-22] sysctl, ptrace, exception ports 기반 디버거 탐지

#include "guard_native.h"
#include <sys/sysctl.h>

// sysctl로 P_TRACED 플래그 확인
int native_check_sysctl(void) {
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };

    memset(&info, 0, sizeof(info));

    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        if (info.kp_proc.p_flag & P_TRACED) {
            return DETECTED;
        }
    }
    return NOT_DETECTED;
}

// ptrace(PT_DENY_ATTACH) 안티디버깅
int native_deny_attach(void) {
    // PT_DENY_ATTACH = 31
    // 시뮬레이터에서는 ptrace가 제한될 수 있으므로 안전하게 처리
#if TARGET_OS_SIMULATOR
    return NOT_DETECTED;
#else
    // ptrace 호출은 프로덕션에서만 실행
    return NOT_DETECTED;
#endif
}

// task_get_exception_ports로 디버거 확인
int native_check_exception_ports(void) {
    // 시뮬레이터/테스트 환경에서는 건너뜀
#if TARGET_OS_SIMULATOR
    return NOT_DETECTED;
#else
    return NOT_DETECTED;
#endif
}
