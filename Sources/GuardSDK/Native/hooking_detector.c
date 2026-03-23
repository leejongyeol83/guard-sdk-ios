// hooking_detector.c
// GuardSDK - 후킹 탐지 C 네이티브 구현
//
// [CL-23] dyld, frida, inline hook, fishhook 기반 후킹 탐지

#include "guard_native.h"
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <TargetConditionals.h>

// _dyld_image_count + _dyld_get_image_name으로 의심 dylib 탐지
int native_check_dyld_hooks(void) {
    const char *suspicious_libs[] = {
        "MobileSubstrate",
        "SubstrateInserter",
        "SubstrateBootstrap",
        "TweakInject",
        "libcycript",
        NULL
    };

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name == NULL) continue;

        for (int j = 0; suspicious_libs[j] != NULL; j++) {
            if (strstr(name, suspicious_libs[j]) != NULL) {
                return DETECTED;
            }
        }
    }
    return NOT_DETECTED;
}

// _dyld_get_image_name에서 frida 패턴 탐지
int native_check_frida_maps(void) {
    const char *frida_libs[] = {
        "frida",
        "FridaGadget",
        "frida-agent",
        NULL
    };

    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name == NULL) continue;

        for (int j = 0; frida_libs[j] != NULL; j++) {
            if (strstr(name, frida_libs[j]) != NULL) {
                return DETECTED;
            }
        }
    }
    return NOT_DETECTED;
}

/**
 * 인라인 후킹 감지 (ARM64 함수 프롤로그 변조 체크)
 *
 * 주요 libSystem 함수의 시작 명령어를 검사하여
 * 분기(B/BR) 명령어로 변조되었는지 확인한다.
 * 인라인 후킹은 함수 시작 부분을 후킹 함수로의
 * 분기 명령어로 교체하는 기법이다.
 *
 * @return DETECTED(1): 프롤로그 변조 발견
 *         NOT_DETECTED(0): 정상
 */
int native_check_inline_hook(void) {
#if TARGET_OS_SIMULATOR
    /* 시뮬레이터(x86_64)에서는 ARM64 프롤로그 검사 불가 */
    return NOT_DETECTED;
#else
    /* 검사할 주요 libSystem 함수 목록 */
    const char *func_names[] = {
        "open", "read", "write", "connect", "ptrace",
        "stat", "access", "dlopen", NULL
    };

    int i;
    for (i = 0; func_names[i] != NULL; i++) {
        void *func_addr = dlsym(RTLD_DEFAULT, func_names[i]);
        if (func_addr == NULL) {
            continue;
        }

        uint32_t *code = (uint32_t *)func_addr;
        uint32_t first_insn = code[0];

        /* ARM64 B 명령어: 0x14000000 ~ 0x17FFFFFF */
        if ((first_insn & 0xFC000000) == 0x14000000) {
            return DETECTED;
        }

        /* ARM64 BL 명령어: 0x94000000 ~ 0x97FFFFFF */
        if ((first_insn & 0xFC000000) == 0x94000000) {
            return DETECTED;
        }

        /* LDR X16, #8 (0x58000050) + BR X16 (0xD61F0200) 트램폴린 */
        if (first_insn == 0x58000050 || first_insn == 0x58000051) {
            uint32_t second_insn = code[1];
            if (second_insn == 0xD61F0200 || second_insn == 0xD61F0220) {
                return DETECTED;
            }
        }

        /* ADRP + ADD/BR 패턴 (Substrate/substitute 방식) */
        /* ADRP: 상위 비트 0x90000000 */
        if ((first_insn & 0x9F000000) == 0x90000000) {
            uint32_t second_insn = code[1];
            /* BR X16/X17 이 두 번째 또는 세 번째 명령어에 있는 경우 */
            if (second_insn == 0xD61F0200 || second_insn == 0xD61F0220) {
                return DETECTED;
            }
            uint32_t third_insn = code[2];
            if (third_insn == 0xD61F0200 || third_insn == 0xD61F0220) {
                return DETECTED;
            }
        }
    }

    return NOT_DETECTED;
#endif
}

/**
 * fishhook 기반 심볼 리바인딩 감지
 *
 * fishhook/substitute 등은 Mach-O lazy/non-lazy symbol pointer를
 * 교체하여 함수 호출을 가로챈다.
 * dlsym으로 얻은 실제 함수 주소와 함수 포인터 호출 주소를 비교하여
 * 리바인딩 여부를 판별한다.
 *
 * @return DETECTED(1): 심볼 리바인딩 발견
 *         NOT_DETECTED(0): 정상
 */
int native_check_fishhook(void) {
#if TARGET_OS_SIMULATOR
    return NOT_DETECTED;
#else
    /* 리바인딩 대상이 되기 쉬운 보안 관련 함수들 */
    const char *target_funcs[] = {
        "open", "stat", "access", "dlopen", "ptrace", NULL
    };

    int i;
    for (i = 0; target_funcs[i] != NULL; i++) {
        /* RTLD_DEFAULT: 기본 심볼 검색 순서로 실제 주소 획득 */
        void *default_addr = dlsym(RTLD_DEFAULT, target_funcs[i]);
        if (default_addr == NULL) {
            continue;
        }

        /* RTLD_NEXT: 다음 라이브러리에서의 주소 획득 */
        void *next_addr = dlsym(RTLD_NEXT, target_funcs[i]);
        if (next_addr == NULL) {
            continue;
        }

        /*
         * 정상: RTLD_DEFAULT == RTLD_NEXT (같은 libSystem 함수)
         * 리바인딩: RTLD_DEFAULT != RTLD_NEXT
         *   - fishhook이 lazy symbol pointer를 교체하면
         *     RTLD_DEFAULT는 후킹 함수를, RTLD_NEXT는 원본을 반환
         */
        if (default_addr != next_addr) {
            return DETECTED;
        }
    }

    return NOT_DETECTED;
#endif
}
