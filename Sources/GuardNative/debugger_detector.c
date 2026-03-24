// debugger_detector.c
// GuardSDK - 디버거 탐지 C 네이티브 구현
//
// [CL-22] sysctl, ptrace, exception ports 기반 디버거 탐지

#include "guard_native.h"
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <TargetConditionals.h>
#include <errno.h>

// ptrace.h는 iOS 실기기에서 제공되지 않으므로 직접 선언
#ifndef PT_DENY_ATTACH
#define PT_DENY_ATTACH 31
#endif
int ptrace(int request, pid_t pid, caddr_t addr, int data);

/**
 * sysctl로 P_TRACED 플래그 확인.
 *
 * 커널의 kinfo_proc 구조체에서 현재 프로세스의 p_flag를 조회하여
 * P_TRACED 비트가 설정되어 있으면 디버거가 연결된 것으로 판단한다.
 *
 * @return DETECTED(1): 디버거 추적 중
 *         NOT_DETECTED(0): 정상
 */
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

/**
 * ptrace(PT_DENY_ATTACH) 안티디버깅.
 *
 * PT_DENY_ATTACH(31)를 호출하면 이후 디버거 연결을 커널 레벨에서 차단한다.
 * 이미 디버거가 연결된 상태에서는 ptrace 호출이 실패(EBUSY)하므로
 * 이를 통해 디버거 연결 여부를 판별한다.
 *
 * 주의: PT_DENY_ATTACH 성공 시 이후 LLDB/GDB 연결이 영구 차단된다.
 *
 * @return DETECTED(1): 디버거가 이미 연결되어 ptrace 실패
 *         NOT_DETECTED(0): 정상 (ptrace 성공 또는 시뮬레이터)
 */
int native_deny_attach(void) {
#if TARGET_OS_SIMULATOR
    /* 시뮬레이터에서는 ptrace가 제한됨 */
    return NOT_DETECTED;
#else
    /*
     * ptrace(PT_DENY_ATTACH) 호출:
     * - 성공(0): 디버거 미연결, 이후 연결 차단됨
     * - 실패(-1, EBUSY/EPERM): 디버거가 이미 연결됨
     */
    int result = ptrace(PT_DENY_ATTACH, 0, 0, 0);
    if (result == -1) {
        /* ptrace 실패 = 디버거가 이미 연결된 상태 */
        return DETECTED;
    }
    /* ptrace 성공 = 디버거 미연결 (이후 연결 차단됨) */
    return NOT_DETECTED;
#endif
}

/**
 * task_get_exception_ports로 디버거 확인.
 *
 * 디버거(LLDB/GDB)가 연결되면 프로세스의 Mach exception port를
 * 수정하여 예외 이벤트를 가로챈다.
 * EXC_MASK_ALL 범위의 exception port가 설정되어 있고,
 * 해당 포트가 현재 태스크의 것이 아니면 디버거가 연결된 것이다.
 *
 * @return DETECTED(1): 비정상 exception port 발견 (디버거 의심)
 *         NOT_DETECTED(0): 정상
 */
int native_check_exception_ports(void) {
#if TARGET_OS_SIMULATOR
    return NOT_DETECTED;
#else
    mach_msg_type_number_t count = 0;
    exception_mask_t masks[EXC_TYPES_COUNT];
    mach_port_t ports[EXC_TYPES_COUNT];
    exception_behavior_t behaviors[EXC_TYPES_COUNT];
    thread_state_flavor_t flavors[EXC_TYPES_COUNT];

    kern_return_t kr = task_get_exception_ports(
        mach_task_self(),
        EXC_MASK_ALL,
        masks,
        &count,
        ports,
        behaviors,
        flavors
    );

    if (kr != KERN_SUCCESS) {
        return NOT_DETECTED;
    }

    /*
     * 정상 앱: exception port가 MACH_PORT_NULL이거나 자기 자신
     * 디버거 연결: exception port가 외부 프로세스(디버거)의 포트로 설정됨
     */
    for (mach_msg_type_number_t i = 0; i < count; i++) {
        if (ports[i] != MACH_PORT_NULL && ports[i] != mach_task_self()) {
            return DETECTED;
        }
    }

    return NOT_DETECTED;
#endif
}
