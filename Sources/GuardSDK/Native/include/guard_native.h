// guard_native.h
// GuardSDK - C 네이티브 공통 헤더
//
// [CL-20] 모든 C 네이티브 탐지 함수의 선언을 포함한다.
// 반환값 규약: 1=탐지, 0=미탐지, -1=오류

#ifndef ANTI_MOBILE_NATIVE_H
#define ANTI_MOBILE_NATIVE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/sysctl.h>

// 반환값 규약
#define DETECTED 1
#define NOT_DETECTED 0
#define CHECK_ERROR -1

// === 탈옥 탐지 ===
int native_check_fork(void);
int native_check_dyld(void);
int native_check_symlinks(void);

// === 디버거 탐지 ===
int native_check_sysctl(void);
int native_deny_attach(void);
int native_check_exception_ports(void);

// === 후킹 탐지 ===
int native_check_dyld_hooks(void);
int native_check_frida_maps(void);
int native_check_inline_hook(void);
int native_check_fishhook(void);

// === 무결성 검증 ===
int native_check_code_signature(void);
int native_check_encryption(void);

#endif // ANTI_MOBILE_NATIVE_H
