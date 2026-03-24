/**
 * jailbreak_detector.c
 * GuardSDK - 탈옥 탐지 C 네이티브 구현
 *
 * [CL-21] 3개 탈옥 탐지 함수:
 *   - native_check_fork(): fork() 호출 가능 여부
 *   - native_check_dyld(): 의심 dylib 로드 확인
 *   - native_check_symlinks(): 시스템 심볼릭 링크 변조 확인
 */

#include "guard_native.h"
#include <dlfcn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <mach-o/dyld.h>

/* ============================================================
 * 탈옥 시 로드되는 의심 동적 라이브러리 이름 목록
 * MobileSubstrate: Cydia Substrate 기반 트윅 로더
 * libcycript: Cycript 인터프리터 라이브러리
 * SubstrateLoader/SubstrateInserter: Substrate 삽입 컴포넌트
 * ============================================================ */
static const char *jailbreak_dylibs[] = {
    "MobileSubstrate",
    "libcycript",
    "SubstrateLoader",
    "SubstrateInserter",
    "TweakInject",
    "libhooker",
    "substitute",
    "Cephei",
    "rocketbootstrap",
    /* Dopamine/ElleKit (iOS 15-16 rootless 탈옥) */
    "ellekit",
    "dopamine",
    /* KernBypass — 탈옥 탐지 우회 트윅 */
    "kernbypass",
    "libkrw",
    NULL
};

/* ============================================================
 * 탈옥 시 존재할 수 있는 시스템 파일/디렉토리 심볼릭 링크 경로
 * 탈옥 도구는 읽기 전용 시스템 파티션에 접근하기 위해
 * 심볼릭 링크를 생성한다.
 * ============================================================ */
static const char *suspicious_symlinks[] = {
    "/etc/fstab",
    "/Applications",
    "/Library/Ringtones",
    "/Library/Wallpaper",
    "/usr/arm-apple-darwin9",
    "/usr/include",
    "/usr/libexec",
    "/usr/share",
    NULL
};

/**
 * fork() 호출 가능 여부 검사.
 *
 * 정상 iOS 앱은 sandbox에 의해 fork() 시스템 콜이 차단된다.
 * 탈옥 환경에서는 sandbox 제한이 해제되어 fork()가 성공한다.
 *
 * 동작:
 *   1. fork() 호출 시도
 *   2. 성공(pid >= 0)이면 탈옥 환경으로 판단
 *   3. 자식 프로세스는 즉시 종료, 부모는 waitpid로 회수
 *
 * @return DETECTED(1): fork 성공 = 탈옥 환경
 *         NOT_DETECTED(0): fork 실패 = 정상 환경
 */
int native_check_fork(void) {
    pid_t pid = fork();

    if (pid >= 0) {
        if (pid == 0) {
            /* 자식 프로세스: 즉시 종료 */
            _exit(0);
        } else {
            /* 부모 프로세스: 자식 프로세스 종료 대기 (좀비 방지) */
            int status;
            waitpid(pid, &status, 0);
        }
        return DETECTED;  /* fork 성공 = 탈옥 환경 */
    }

    return NOT_DETECTED;  /* fork 실패 = 정상 sandbox 환경 */
}

/**
 * _dyld_image_count + _dyld_get_image_name으로 의심 dylib 탐지.
 *
 * 탈옥 환경에서는 MobileSubstrate, Cycript 등의 동적 라이브러리가
 * dyld에 의해 자동으로 로드된다.
 * 현재 프로세스에 로드된 모든 이미지의 이름을 검사하여
 * 탈옥 관련 dylib가 포함되어 있는지 확인한다.
 *
 * @return DETECTED(1): 의심 dylib 발견
 *         NOT_DETECTED(0): 의심 dylib 없음
 *         CHECK_ERROR(-1): 검사 실패
 */
int native_check_dyld(void) {
    uint32_t count = _dyld_image_count();

    if (count == 0) {
        return CHECK_ERROR;  /* 비정상 상태: dyld 이미지가 하나도 없음 */
    }

    for (uint32_t i = 0; i < count; i++) {
        const char *image_name = _dyld_get_image_name(i);
        if (image_name == NULL) {
            continue;
        }

        /* 의심 dylib 목록과 비교 */
        for (int j = 0; jailbreak_dylibs[j] != NULL; j++) {
            if (strstr(image_name, jailbreak_dylibs[j]) != NULL) {
                return DETECTED;  /* 탈옥 관련 dylib 발견 */
            }
        }
    }

    return NOT_DETECTED;
}

/**
 * 시스템 파일/디렉토리의 심볼릭 링크 변조 확인.
 *
 * 탈옥 도구(예: Cydia, unc0ver, checkra1n)는 시스템 파티션의
 * 읽기 전용 제한을 우회하기 위해 주요 시스템 경로를
 * 심볼릭 링크로 교체한다.
 *
 * lstat()로 파일의 실제 타입을 확인하여 심볼릭 링크 여부를 판단한다.
 * (stat()은 심볼릭 링크를 따라가므로 lstat() 사용)
 *
 * @return DETECTED(1): 심볼릭 링크 변조 발견
 *         NOT_DETECTED(0): 정상
 */
int native_check_symlinks(void) {
    struct stat sb;

    for (int i = 0; suspicious_symlinks[i] != NULL; i++) {
        if (lstat(suspicious_symlinks[i], &sb) == 0) {
            if (S_ISLNK(sb.st_mode)) {
                return DETECTED;  /* 심볼릭 링크 발견 = 탈옥 의심 */
            }
        }
    }

    return NOT_DETECTED;
}
