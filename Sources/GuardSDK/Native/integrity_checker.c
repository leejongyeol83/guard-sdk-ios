// integrity_checker.c
// GuardSDK - 무결성 검증 C 네이티브 구현
//
// [CL-24] Mach-O 로드 커맨드 기반 코드 서명 및 암호화 검증

#include "guard_native.h"
#include <mach-o/dyld.h>
#include <mach-o/loader.h>

// LC_CODE_SIGNATURE 로드 커맨드 검증
int native_check_code_signature(void) {
    // 메인 바이너리의 Mach-O 헤더를 검사한다
    const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (header == NULL) {
        return CHECK_ERROR;
    }

    // 로드 커맨드를 순회하며 LC_CODE_SIGNATURE를 찾는다
    const uint8_t *ptr = (const uint8_t *)header + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *cmd = (const struct load_command *)ptr;
        if (cmd->cmd == LC_CODE_SIGNATURE) {
            // 코드 서명이 존재함 (정상)
            return NOT_DETECTED;
        }
        ptr += cmd->cmdsize;
    }

    // LC_CODE_SIGNATURE가 없음 (변조 의심)
    return DETECTED;
}

// LC_ENCRYPTION_INFO_64 확인 (암호화 해제 여부)
int native_check_encryption(void) {
    const struct mach_header_64 *header = (const struct mach_header_64 *)_dyld_get_image_header(0);
    if (header == NULL) {
        return CHECK_ERROR;
    }

    const uint8_t *ptr = (const uint8_t *)header + sizeof(struct mach_header_64);
    for (uint32_t i = 0; i < header->ncmds; i++) {
        const struct load_command *cmd = (const struct load_command *)ptr;
        if (cmd->cmd == LC_ENCRYPTION_INFO_64) {
            const struct encryption_info_command_64 *enc =
                (const struct encryption_info_command_64 *)cmd;
            if (enc->cryptid == 0) {
                // 암호화가 해제됨 (크랙된 앱)
                return DETECTED;
            }
            return NOT_DETECTED;
        }
        ptr += cmd->cmdsize;
    }

    // 암호화 정보가 없음 (개발 빌드에서는 정상)
    return NOT_DETECTED;
}
