/*
 * Assembly trampolines for dwmapi.dll proxy exports.
 * Each export is a naked jmp through the mProcs[] function pointer array,
 * preserving all registers and stack — works for any calling convention/signature.
 *
 * Made by Wilhelm-af
 *
 * mProcs is defined in dwmapi.cpp as: extern "C" uintptr_t mProcs[143]
 * The .def file maps export names to these symbols: ExportName=f0 @ordinal
 */

.text

/* ___chkstk_ms — stack probe for large stack allocations (normally in libgcc).
 * GCC inserts calls to this when a function needs > 4KB of stack.
 * With -nostdlib we must provide it ourselves. */
.globl ___chkstk_ms
___chkstk_ms:
    push    %rcx
    push    %rax
    cmp     $0x1000, %rax
    lea     24(%rsp), %rcx
    jb      1f
2:
    sub     $0x1000, %rcx
    test    %rcx, (%rcx)
    sub     $0x1000, %rax
    cmp     $0x1000, %rax
    ja      2b
1:
    sub     %rax, %rcx
    test    %rcx, (%rcx)
    pop     %rax
    pop     %rcx
    ret

.macro tramp name, index
    .globl \name
    \name:
        jmpq *mProcs+(\index * 8)(%rip)
.endm

/* Named exports (44 functions) — index 0-43 */
tramp f0,  0    /* @1   DwmpDxGetWindowSharedSurface       */
tramp f1,  1    /* @2   DwmpDxUpdateWindowSharedSurface    */
tramp f2,  2    /* @3   DwmEnableComposition               */
tramp f3,  3    /* @12  DllCanUnloadNow                    */
tramp f4,  4    /* @16  DllGetClassObject                  */
tramp f5,  5    /* @17  DwmAttachMilContent                */
tramp f6,  6    /* @18  DwmDefWindowProc                   */
tramp f7,  7    /* @19  DwmDetachMilContent                */
tramp f8,  8    /* @20  DwmEnableBlurBehindWindow          */
tramp f9,  9    /* @21  DwmEnableMMCSS                     */
tramp f10, 10   /* @22  DwmExtendFrameIntoClientArea       */
tramp f11, 11   /* @23  DwmFlush                           */
tramp f12, 12   /* @24  DwmGetColorizationColor            */
tramp f13, 13   /* @26  DwmGetCompositionTimingInfo        */
tramp f14, 14   /* @27  DwmGetGraphicsStreamClient         */
tramp f15, 15   /* @28  DwmpGetColorizationParameters      */
tramp f16, 16   /* @29  DwmpDxgiIsThreadDesktopComposited  */
tramp f17, 17   /* @30  DwmGetGraphicsStreamTransformHint  */
tramp f18, 18   /* @31  DwmGetTransportAttributes          */
tramp f19, 19   /* @32  DwmpSetColorizationParameters      */
tramp f20, 20   /* @34  DwmGetUnmetTabRequirements         */
tramp f21, 21   /* @35  DwmGetWindowAttribute              */
tramp f22, 22   /* @36  DwmpRenderFlick                    */
tramp f23, 23   /* @37  DwmpAllocateSecurityDescriptor     */
tramp f24, 24   /* @38  DwmpFreeSecurityDescriptor         */
tramp f25, 25   /* @44  DwmpEnableDDASupport               */
tramp f26, 26   /* @50  DwmInvalidateIconicBitmaps         */
tramp f27, 27   /* @57  DwmTetherTextContact               */
tramp f28, 28   /* @84  DwmpUpdateProxyWindowForCapture    */
tramp f29, 29   /* @85  DwmIsCompositionEnabled            */
tramp f30, 30   /* @86  DwmModifyPreviousDxFrameDuration   */
tramp f31, 31   /* @87  DwmQueryThumbnailSourceSize        */
tramp f32, 32   /* @88  DwmRegisterThumbnail               */
tramp f33, 33   /* @89  DwmRenderGesture                   */
tramp f34, 34   /* @90  DwmSetDxFrameDuration              */
tramp f35, 35   /* @91  DwmSetIconicLivePreviewBitmap      */
tramp f36, 36   /* @92  DwmSetIconicThumbnail              */
tramp f37, 37   /* @93  DwmSetPresentParameters            */
tramp f38, 38   /* @94  DwmSetWindowAttribute              */
tramp f39, 39   /* @95  DwmShowContact                     */
tramp f40, 40   /* @96  DwmTetherContact                   */
tramp f41, 41   /* @97  DwmTransitionOwnedWindow           */
tramp f42, 42   /* @98  DwmUnregisterThumbnail             */
tramp f43, 43   /* @99  DwmUpdateThumbnailProperties       */

/* Ordinal-only exports (99 functions) — index 44-142, ordinals 100-198 */
tramp f44,  44
tramp f45,  45
tramp f46,  46
tramp f47,  47
tramp f48,  48
tramp f49,  49
tramp f50,  50
tramp f51,  51
tramp f52,  52
tramp f53,  53
tramp f54,  54
tramp f55,  55
tramp f56,  56
tramp f57,  57
tramp f58,  58
tramp f59,  59
tramp f60,  60
tramp f61,  61
tramp f62,  62
tramp f63,  63
tramp f64,  64
tramp f65,  65
tramp f66,  66
tramp f67,  67
tramp f68,  68
tramp f69,  69
tramp f70,  70
tramp f71,  71
tramp f72,  72
tramp f73,  73
tramp f74,  74
tramp f75,  75
tramp f76,  76
tramp f77,  77
tramp f78,  78
tramp f79,  79
tramp f80,  80
tramp f81,  81
tramp f82,  82
tramp f83,  83
tramp f84,  84
tramp f85,  85
tramp f86,  86
tramp f87,  87
tramp f88,  88
tramp f89,  89
tramp f90,  90
tramp f91,  91
tramp f92,  92
tramp f93,  93
tramp f94,  94
tramp f95,  95
tramp f96,  96
tramp f97,  97
tramp f98,  98
tramp f99,  99
tramp f100, 100
tramp f101, 101
tramp f102, 102
tramp f103, 103
tramp f104, 104
tramp f105, 105
tramp f106, 106
tramp f107, 107
tramp f108, 108
tramp f109, 109
tramp f110, 110
tramp f111, 111
tramp f112, 112
tramp f113, 113
tramp f114, 114
tramp f115, 115
tramp f116, 116
tramp f117, 117
tramp f118, 118
tramp f119, 119
tramp f120, 120
tramp f121, 121
tramp f122, 122
tramp f123, 123
tramp f124, 124
tramp f125, 125
tramp f126, 126
tramp f127, 127
tramp f128, 128
tramp f129, 129
tramp f130, 130
tramp f131, 131
tramp f132, 132
tramp f133, 133
tramp f134, 134
tramp f135, 135
tramp f136, 136
tramp f137, 137
tramp f138, 138
tramp f139, 139
tramp f140, 140
tramp f141, 141
tramp f142, 142
