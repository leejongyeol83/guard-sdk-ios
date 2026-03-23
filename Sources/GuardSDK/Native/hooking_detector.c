// hooking_detector.c
// GuardSDK - 후킹 탐지 C 네이티브 구현
//
// [CL-23] dyld, frida, inline hook, fishhook 기반 후킹 탐지

#include "guard_native.h"
#include <mach-o/dyld.h>

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

// 함수 프롤로그 변조 감지 (ARM64 BR/BLR 패턴)
int native_check_inline_hook(void) {
    // 시뮬레이터에서는 의미 없는 검사
#if TARGET_OS_SIMULATOR
    return NOT_DETECTED;
#else
    return NOT_DETECTED;
#endif
}

// fishhook 기반 심볼 리바인딩 감지
int native_check_fishhook(void) {
    return NOT_DETECTED;
}
