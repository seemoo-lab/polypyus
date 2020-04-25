"""
Sweep binary from known code locations for further matches
"""
import cProfile
import struct
from dataclasses import dataclass, field
from heapq import heapify, heappop, heappush
from operator import add, itemgetter
from typing import Iterable, List, Set

from capstone import (CS_ARCH_ARM, CS_GRP_CALL, CS_GRP_INT, CS_GRP_JUMP,
                      CS_GRP_RET, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN,
                      CS_MODE_THUMB, Cs, CsInsn)
from capstone.arm import *
from capstone.arm import (ARM_CC_AL, ARM_INS_ADC, ARM_INS_ADD, ARM_INS_ADDW,
                          ARM_INS_ADR, ARM_INS_AESD, ARM_INS_AESE,
                          ARM_INS_AESIMC, ARM_INS_AESMC, ARM_INS_AND,
                          ARM_INS_ASR, ARM_INS_B, ARM_INS_BFC, ARM_INS_BFI,
                          ARM_INS_BIC, ARM_INS_BKPT, ARM_INS_BL, ARM_INS_BLX,
                          ARM_INS_BX, ARM_INS_BXJ, ARM_INS_CBNZ, ARM_INS_CBZ,
                          ARM_INS_CDP, ARM_INS_CDP2, ARM_INS_CLREX,
                          ARM_INS_CLZ, ARM_INS_CMN, ARM_INS_CMP, ARM_INS_CPS,
                          ARM_INS_CRC32B, ARM_INS_CRC32CB, ARM_INS_CRC32CH,
                          ARM_INS_CRC32CW, ARM_INS_CRC32H, ARM_INS_CRC32W,
                          ARM_INS_DBG, ARM_INS_DCPS1, ARM_INS_DCPS2,
                          ARM_INS_DCPS3, ARM_INS_DMB, ARM_INS_DSB,
                          ARM_INS_ENDING, ARM_INS_EOR, ARM_INS_ERET,
                          ARM_INS_FLDMDBX, ARM_INS_FLDMIAX, ARM_INS_FSTMDBX,
                          ARM_INS_FSTMIAX, ARM_INS_HINT, ARM_INS_HLT,
                          ARM_INS_HVC, ARM_INS_INVALID, ARM_INS_ISB,
                          ARM_INS_IT, ARM_INS_LDA, ARM_INS_LDAB, ARM_INS_LDAEX,
                          ARM_INS_LDAEXB, ARM_INS_LDAEXD, ARM_INS_LDAEXH,
                          ARM_INS_LDAH, ARM_INS_LDC, ARM_INS_LDC2,
                          ARM_INS_LDC2L, ARM_INS_LDCL, ARM_INS_LDM,
                          ARM_INS_LDMDA, ARM_INS_LDMDB, ARM_INS_LDMIB,
                          ARM_INS_LDR, ARM_INS_LDRB, ARM_INS_LDRBT,
                          ARM_INS_LDRD, ARM_INS_LDREX, ARM_INS_LDREXB,
                          ARM_INS_LDREXD, ARM_INS_LDREXH, ARM_INS_LDRH,
                          ARM_INS_LDRHT, ARM_INS_LDRSB, ARM_INS_LDRSBT,
                          ARM_INS_LDRSH, ARM_INS_LDRSHT, ARM_INS_LDRT,
                          ARM_INS_LSL, ARM_INS_LSR, ARM_INS_MCR, ARM_INS_MCR2,
                          ARM_INS_MCRR, ARM_INS_MCRR2, ARM_INS_MLA,
                          ARM_INS_MLS, ARM_INS_MOV, ARM_INS_MOVT, ARM_INS_MOVW,
                          ARM_INS_MRC, ARM_INS_MRC2, ARM_INS_MRRC,
                          ARM_INS_MRRC2, ARM_INS_MRS, ARM_INS_MSR, ARM_INS_MUL,
                          ARM_INS_MVN, ARM_INS_NOP, ARM_INS_ORN, ARM_INS_ORR,
                          ARM_INS_PKHBT, ARM_INS_PKHTB, ARM_INS_PLD,
                          ARM_INS_PLDW, ARM_INS_PLI, ARM_INS_POP, ARM_INS_PUSH,
                          ARM_INS_QADD, ARM_INS_QADD8, ARM_INS_QADD16,
                          ARM_INS_QASX, ARM_INS_QDADD, ARM_INS_QDSUB,
                          ARM_INS_QSAX, ARM_INS_QSUB, ARM_INS_QSUB8,
                          ARM_INS_QSUB16, ARM_INS_RBIT, ARM_INS_REV,
                          ARM_INS_REV16, ARM_INS_REVSH, ARM_INS_RFEDA,
                          ARM_INS_RFEDB, ARM_INS_RFEIA, ARM_INS_RFEIB,
                          ARM_INS_ROR, ARM_INS_RRX, ARM_INS_RSB, ARM_INS_RSC,
                          ARM_INS_SADD8, ARM_INS_SADD16, ARM_INS_SASX,
                          ARM_INS_SBC, ARM_INS_SBFX, ARM_INS_SDIV, ARM_INS_SEL,
                          ARM_INS_SETEND, ARM_INS_SEV, ARM_INS_SEVL,
                          ARM_INS_SHA1C, ARM_INS_SHA1H, ARM_INS_SHA1M,
                          ARM_INS_SHA1P, ARM_INS_SHA1SU0, ARM_INS_SHA1SU1,
                          ARM_INS_SHA256H, ARM_INS_SHA256H2, ARM_INS_SHA256SU0,
                          ARM_INS_SHA256SU1, ARM_INS_SHADD8, ARM_INS_SHADD16,
                          ARM_INS_SHASX, ARM_INS_SHSAX, ARM_INS_SHSUB8,
                          ARM_INS_SHSUB16, ARM_INS_SMC, ARM_INS_SMLABB,
                          ARM_INS_SMLABT, ARM_INS_SMLAD, ARM_INS_SMLADX,
                          ARM_INS_SMLAL, ARM_INS_SMLALBB, ARM_INS_SMLALBT,
                          ARM_INS_SMLALD, ARM_INS_SMLALDX, ARM_INS_SMLALTB,
                          ARM_INS_SMLALTT, ARM_INS_SMLATB, ARM_INS_SMLATT,
                          ARM_INS_SMLAWB, ARM_INS_SMLAWT, ARM_INS_SMLSD,
                          ARM_INS_SMLSDX, ARM_INS_SMLSLD, ARM_INS_SMLSLDX,
                          ARM_INS_SMMLA, ARM_INS_SMMLAR, ARM_INS_SMMLS,
                          ARM_INS_SMMLSR, ARM_INS_SMMUL, ARM_INS_SMMULR,
                          ARM_INS_SMUAD, ARM_INS_SMUADX, ARM_INS_SMULBB,
                          ARM_INS_SMULBT, ARM_INS_SMULL, ARM_INS_SMULTB,
                          ARM_INS_SMULTT, ARM_INS_SMULWB, ARM_INS_SMULWT,
                          ARM_INS_SMUSD, ARM_INS_SMUSDX, ARM_INS_SRSDA,
                          ARM_INS_SRSDB, ARM_INS_SRSIA, ARM_INS_SRSIB,
                          ARM_INS_SSAT, ARM_INS_SSAT16, ARM_INS_SSAX,
                          ARM_INS_SSUB8, ARM_INS_SSUB16, ARM_INS_STC,
                          ARM_INS_STC2, ARM_INS_STC2L, ARM_INS_STCL,
                          ARM_INS_STL, ARM_INS_STLB, ARM_INS_STLEX,
                          ARM_INS_STLEXB, ARM_INS_STLEXD, ARM_INS_STLEXH,
                          ARM_INS_STLH, ARM_INS_STM, ARM_INS_STMDA,
                          ARM_INS_STMDB, ARM_INS_STMIB, ARM_INS_STR,
                          ARM_INS_STRB, ARM_INS_STRBT, ARM_INS_STRD,
                          ARM_INS_STREX, ARM_INS_STREXB, ARM_INS_STREXD,
                          ARM_INS_STREXH, ARM_INS_STRH, ARM_INS_STRHT,
                          ARM_INS_STRT, ARM_INS_SUB, ARM_INS_SUBW, ARM_INS_SVC,
                          ARM_INS_SWP, ARM_INS_SWPB, ARM_INS_SXTAB,
                          ARM_INS_SXTAB16, ARM_INS_SXTAH, ARM_INS_SXTB,
                          ARM_INS_SXTB16, ARM_INS_SXTH, ARM_INS_TBB,
                          ARM_INS_TBH, ARM_INS_TEQ, ARM_INS_TRAP, ARM_INS_TST,
                          ARM_INS_UADD8, ARM_INS_UADD16, ARM_INS_UASX,
                          ARM_INS_UBFX, ARM_INS_UDF, ARM_INS_UDIV,
                          ARM_INS_UHADD8, ARM_INS_UHADD16, ARM_INS_UHASX,
                          ARM_INS_UHSAX, ARM_INS_UHSUB8, ARM_INS_UHSUB16,
                          ARM_INS_UMAAL, ARM_INS_UMLAL, ARM_INS_UMULL,
                          ARM_INS_UQADD8, ARM_INS_UQADD16, ARM_INS_UQASX,
                          ARM_INS_UQSAX, ARM_INS_UQSUB8, ARM_INS_UQSUB16,
                          ARM_INS_USAD8, ARM_INS_USADA8, ARM_INS_USAT,
                          ARM_INS_USAT16, ARM_INS_USAX, ARM_INS_USUB8,
                          ARM_INS_USUB16, ARM_INS_UXTAB, ARM_INS_UXTAB16,
                          ARM_INS_UXTAH, ARM_INS_UXTB, ARM_INS_UXTB16,
                          ARM_INS_UXTH, ARM_INS_VABA, ARM_INS_VABAL,
                          ARM_INS_VABD, ARM_INS_VABDL, ARM_INS_VABS,
                          ARM_INS_VACGE, ARM_INS_VACGT, ARM_INS_VADD,
                          ARM_INS_VADDHN, ARM_INS_VADDL, ARM_INS_VADDW,
                          ARM_INS_VAND, ARM_INS_VBIC, ARM_INS_VBIF,
                          ARM_INS_VBIT, ARM_INS_VBSL, ARM_INS_VCEQ,
                          ARM_INS_VCGE, ARM_INS_VCGT, ARM_INS_VCLE,
                          ARM_INS_VCLS, ARM_INS_VCLT, ARM_INS_VCLZ,
                          ARM_INS_VCMP, ARM_INS_VCMPE, ARM_INS_VCNT,
                          ARM_INS_VCVT, ARM_INS_VCVTA, ARM_INS_VCVTB,
                          ARM_INS_VCVTM, ARM_INS_VCVTN, ARM_INS_VCVTP,
                          ARM_INS_VCVTR, ARM_INS_VCVTT, ARM_INS_VDIV,
                          ARM_INS_VDUP, ARM_INS_VEOR, ARM_INS_VEXT,
                          ARM_INS_VFMA, ARM_INS_VFMS, ARM_INS_VFNMA,
                          ARM_INS_VFNMS, ARM_INS_VHADD, ARM_INS_VHSUB,
                          ARM_INS_VLD1, ARM_INS_VLD2, ARM_INS_VLD3,
                          ARM_INS_VLD4, ARM_INS_VLDMDB, ARM_INS_VLDMIA,
                          ARM_INS_VLDR, ARM_INS_VMAX, ARM_INS_VMAXNM,
                          ARM_INS_VMIN, ARM_INS_VMINNM, ARM_INS_VMLA,
                          ARM_INS_VMLAL, ARM_INS_VMLS, ARM_INS_VMLSL,
                          ARM_INS_VMOV, ARM_INS_VMOVL, ARM_INS_VMOVN,
                          ARM_INS_VMRS, ARM_INS_VMSR, ARM_INS_VMUL,
                          ARM_INS_VMULL, ARM_INS_VMVN, ARM_INS_VNEG,
                          ARM_INS_VNMLA, ARM_INS_VNMLS, ARM_INS_VNMUL,
                          ARM_INS_VORN, ARM_INS_VORR, ARM_INS_VPADAL,
                          ARM_INS_VPADD, ARM_INS_VPADDL, ARM_INS_VPMAX,
                          ARM_INS_VPMIN, ARM_INS_VPOP, ARM_INS_VPUSH,
                          ARM_INS_VQABS, ARM_INS_VQADD, ARM_INS_VQDMLAL,
                          ARM_INS_VQDMLSL, ARM_INS_VQDMULH, ARM_INS_VQDMULL,
                          ARM_INS_VQMOVN, ARM_INS_VQMOVUN, ARM_INS_VQNEG,
                          ARM_INS_VQRDMULH, ARM_INS_VQRSHL, ARM_INS_VQRSHRN,
                          ARM_INS_VQRSHRUN, ARM_INS_VQSHL, ARM_INS_VQSHLU,
                          ARM_INS_VQSHRN, ARM_INS_VQSHRUN, ARM_INS_VQSUB,
                          ARM_INS_VRADDHN, ARM_INS_VRECPE, ARM_INS_VRECPS,
                          ARM_INS_VREV16, ARM_INS_VREV32, ARM_INS_VREV64,
                          ARM_INS_VRHADD, ARM_INS_VRINTA, ARM_INS_VRINTM,
                          ARM_INS_VRINTN, ARM_INS_VRINTP, ARM_INS_VRINTR,
                          ARM_INS_VRINTX, ARM_INS_VRINTZ, ARM_INS_VRSHL,
                          ARM_INS_VRSHR, ARM_INS_VRSHRN, ARM_INS_VRSQRTE,
                          ARM_INS_VRSQRTS, ARM_INS_VRSRA, ARM_INS_VRSUBHN,
                          ARM_INS_VSELEQ, ARM_INS_VSELGE, ARM_INS_VSELGT,
                          ARM_INS_VSELVS, ARM_INS_VSHL, ARM_INS_VSHLL,
                          ARM_INS_VSHR, ARM_INS_VSHRN, ARM_INS_VSLI,
                          ARM_INS_VSQRT, ARM_INS_VSRA, ARM_INS_VSRI,
                          ARM_INS_VST1, ARM_INS_VST2, ARM_INS_VST3,
                          ARM_INS_VST4, ARM_INS_VSTMDB, ARM_INS_VSTMIA,
                          ARM_INS_VSTR, ARM_INS_VSUB, ARM_INS_VSUBHN,
                          ARM_INS_VSUBL, ARM_INS_VSUBW, ARM_INS_VSWP,
                          ARM_INS_VTBL, ARM_INS_VTBX, ARM_INS_VTRN,
                          ARM_INS_VTST, ARM_INS_VUZP, ARM_INS_VZIP,
                          ARM_INS_WFE, ARM_INS_WFI, ARM_INS_YIELD)
from intervaltree import IntervalTree
from polypyus.models import Binary, Match

mnemonic_store = {
    ARM_INS_INVALID: "invalid",
    ARM_INS_ADC: "adc",
    ARM_INS_ADD: "add",
    ARM_INS_ADR: "adr",
    ARM_INS_AESD: "aesd",
    ARM_INS_AESE: "aese",
    ARM_INS_AESIMC: "aesimc",
    ARM_INS_AESMC: "aesmc",
    ARM_INS_AND: "and",
    ARM_INS_BFC: "bfc",
    ARM_INS_BFI: "bfi",
    ARM_INS_BIC: "bic",
    ARM_INS_BKPT: "bkpt",
    ARM_INS_BL: "bl",
    ARM_INS_BLX: "blx",
    ARM_INS_BX: "bx",
    ARM_INS_BXJ: "bxj",
    ARM_INS_B: "b",
    ARM_INS_CDP: "cdp",
    ARM_INS_CDP2: "cdp2",
    ARM_INS_CLREX: "clrex",
    ARM_INS_CLZ: "clz",
    ARM_INS_CMN: "cmn",
    ARM_INS_CMP: "cmp",
    ARM_INS_CPS: "cps",
    ARM_INS_CRC32B: "crc32b",
    ARM_INS_CRC32CB: "crc32cb",
    ARM_INS_CRC32CH: "crc32ch",
    ARM_INS_CRC32CW: "crc32cw",
    ARM_INS_CRC32H: "crc32h",
    ARM_INS_CRC32W: "crc32w",
    ARM_INS_DBG: "dbg",
    ARM_INS_DMB: "dmb",
    ARM_INS_DSB: "dsb",
    ARM_INS_EOR: "eor",
    ARM_INS_ERET: "eret",
    ARM_INS_VMOV: "vmov",
    ARM_INS_FLDMDBX: "fldmdbx",
    ARM_INS_FLDMIAX: "fldmiax",
    ARM_INS_VMRS: "vmrs",
    ARM_INS_FSTMDBX: "fstmdbx",
    ARM_INS_FSTMIAX: "fstmiax",
    ARM_INS_HINT: "hint",
    ARM_INS_HLT: "hlt",
    ARM_INS_HVC: "hvc",
    ARM_INS_ISB: "isb",
    ARM_INS_LDA: "lda",
    ARM_INS_LDAB: "ldab",
    ARM_INS_LDAEX: "ldaex",
    ARM_INS_LDAEXB: "ldaexb",
    ARM_INS_LDAEXD: "ldaexd",
    ARM_INS_LDAEXH: "ldaexh",
    ARM_INS_LDAH: "ldah",
    ARM_INS_LDC2L: "ldc2l",
    ARM_INS_LDC2: "ldc2",
    ARM_INS_LDCL: "ldcl",
    ARM_INS_LDC: "ldc",
    ARM_INS_LDMDA: "ldmda",
    ARM_INS_LDMDB: "ldmdb",
    ARM_INS_LDM: "ldm",
    ARM_INS_LDMIB: "ldmib",
    ARM_INS_LDRBT: "ldrbt",
    ARM_INS_LDRB: "ldrb",
    ARM_INS_LDRD: "ldrd",
    ARM_INS_LDREX: "ldrex",
    ARM_INS_LDREXB: "ldrexb",
    ARM_INS_LDREXD: "ldrexd",
    ARM_INS_LDREXH: "ldrexh",
    ARM_INS_LDRH: "ldrh",
    ARM_INS_LDRHT: "ldrht",
    ARM_INS_LDRSB: "ldrsb",
    ARM_INS_LDRSBT: "ldrsbt",
    ARM_INS_LDRSH: "ldrsh",
    ARM_INS_LDRSHT: "ldrsht",
    ARM_INS_LDRT: "ldrt",
    ARM_INS_LDR: "ldr",
    ARM_INS_MCR: "mcr",
    ARM_INS_MCR2: "mcr2",
    ARM_INS_MCRR: "mcrr",
    ARM_INS_MCRR2: "mcrr2",
    ARM_INS_MLA: "mla",
    ARM_INS_MLS: "mls",
    ARM_INS_MOV: "mov",
    ARM_INS_MOVT: "movt",
    ARM_INS_MOVW: "movw",
    ARM_INS_MRC: "mrc",
    ARM_INS_MRC2: "mrc2",
    ARM_INS_MRRC: "mrrc",
    ARM_INS_MRRC2: "mrrc2",
    ARM_INS_MRS: "mrs",
    ARM_INS_MSR: "msr",
    ARM_INS_MUL: "mul",
    ARM_INS_MVN: "mvn",
    ARM_INS_ORR: "orr",
    ARM_INS_PKHBT: "pkhbt",
    ARM_INS_PKHTB: "pkhtb",
    ARM_INS_PLDW: "pldw",
    ARM_INS_PLD: "pld",
    ARM_INS_PLI: "pli",
    ARM_INS_QADD: "qadd",
    ARM_INS_QADD16: "qadd16",
    ARM_INS_QADD8: "qadd8",
    ARM_INS_QASX: "qasx",
    ARM_INS_QDADD: "qdadd",
    ARM_INS_QDSUB: "qdsub",
    ARM_INS_QSAX: "qsax",
    ARM_INS_QSUB: "qsub",
    ARM_INS_QSUB16: "qsub16",
    ARM_INS_QSUB8: "qsub8",
    ARM_INS_RBIT: "rbit",
    ARM_INS_REV: "rev",
    ARM_INS_REV16: "rev16",
    ARM_INS_REVSH: "revsh",
    ARM_INS_RFEDA: "rfeda",
    ARM_INS_RFEDB: "rfedb",
    ARM_INS_RFEIA: "rfeia",
    ARM_INS_RFEIB: "rfeib",
    ARM_INS_RSB: "rsb",
    ARM_INS_RSC: "rsc",
    ARM_INS_SADD16: "sadd16",
    ARM_INS_SADD8: "sadd8",
    ARM_INS_SASX: "sasx",
    ARM_INS_SBC: "sbc",
    ARM_INS_SBFX: "sbfx",
    ARM_INS_SDIV: "sdiv",
    ARM_INS_SEL: "sel",
    ARM_INS_SETEND: "setend",
    ARM_INS_SHA1C: "sha1c",
    ARM_INS_SHA1H: "sha1h",
    ARM_INS_SHA1M: "sha1m",
    ARM_INS_SHA1P: "sha1p",
    ARM_INS_SHA1SU0: "sha1su0",
    ARM_INS_SHA1SU1: "sha1su1",
    ARM_INS_SHA256H: "sha256h",
    ARM_INS_SHA256H2: "sha256h2",
    ARM_INS_SHA256SU0: "sha256su0",
    ARM_INS_SHA256SU1: "sha256su1",
    ARM_INS_SHADD16: "shadd16",
    ARM_INS_SHADD8: "shadd8",
    ARM_INS_SHASX: "shasx",
    ARM_INS_SHSAX: "shsax",
    ARM_INS_SHSUB16: "shsub16",
    ARM_INS_SHSUB8: "shsub8",
    ARM_INS_SMC: "smc",
    ARM_INS_SMLABB: "smlabb",
    ARM_INS_SMLABT: "smlabt",
    ARM_INS_SMLAD: "smlad",
    ARM_INS_SMLADX: "smladx",
    ARM_INS_SMLAL: "smlal",
    ARM_INS_SMLALBB: "smlalbb",
    ARM_INS_SMLALBT: "smlalbt",
    ARM_INS_SMLALD: "smlald",
    ARM_INS_SMLALDX: "smlaldx",
    ARM_INS_SMLALTB: "smlaltb",
    ARM_INS_SMLALTT: "smlaltt",
    ARM_INS_SMLATB: "smlatb",
    ARM_INS_SMLATT: "smlatt",
    ARM_INS_SMLAWB: "smlawb",
    ARM_INS_SMLAWT: "smlawt",
    ARM_INS_SMLSD: "smlsd",
    ARM_INS_SMLSDX: "smlsdx",
    ARM_INS_SMLSLD: "smlsld",
    ARM_INS_SMLSLDX: "smlsldx",
    ARM_INS_SMMLA: "smmla",
    ARM_INS_SMMLAR: "smmlar",
    ARM_INS_SMMLS: "smmls",
    ARM_INS_SMMLSR: "smmlsr",
    ARM_INS_SMMUL: "smmul",
    ARM_INS_SMMULR: "smmulr",
    ARM_INS_SMUAD: "smuad",
    ARM_INS_SMUADX: "smuadx",
    ARM_INS_SMULBB: "smulbb",
    ARM_INS_SMULBT: "smulbt",
    ARM_INS_SMULL: "smull",
    ARM_INS_SMULTB: "smultb",
    ARM_INS_SMULTT: "smultt",
    ARM_INS_SMULWB: "smulwb",
    ARM_INS_SMULWT: "smulwt",
    ARM_INS_SMUSD: "smusd",
    ARM_INS_SMUSDX: "smusdx",
    ARM_INS_SRSDA: "srsda",
    ARM_INS_SRSDB: "srsdb",
    ARM_INS_SRSIA: "srsia",
    ARM_INS_SRSIB: "srsib",
    ARM_INS_SSAT: "ssat",
    ARM_INS_SSAT16: "ssat16",
    ARM_INS_SSAX: "ssax",
    ARM_INS_SSUB16: "ssub16",
    ARM_INS_SSUB8: "ssub8",
    ARM_INS_STC2L: "stc2l",
    ARM_INS_STC2: "stc2",
    ARM_INS_STCL: "stcl",
    ARM_INS_STC: "stc",
    ARM_INS_STL: "stl",
    ARM_INS_STLB: "stlb",
    ARM_INS_STLEX: "stlex",
    ARM_INS_STLEXB: "stlexb",
    ARM_INS_STLEXD: "stlexd",
    ARM_INS_STLEXH: "stlexh",
    ARM_INS_STLH: "stlh",
    ARM_INS_STMDA: "stmda",
    ARM_INS_STMDB: "stmdb",
    ARM_INS_STM: "stm",
    ARM_INS_STMIB: "stmib",
    ARM_INS_STRBT: "strbt",
    ARM_INS_STRB: "strb",
    ARM_INS_STRD: "strd",
    ARM_INS_STREX: "strex",
    ARM_INS_STREXB: "strexb",
    ARM_INS_STREXD: "strexd",
    ARM_INS_STREXH: "strexh",
    ARM_INS_STRH: "strh",
    ARM_INS_STRHT: "strht",
    ARM_INS_STRT: "strt",
    ARM_INS_STR: "str",
    ARM_INS_SUB: "sub",
    ARM_INS_SVC: "svc",
    ARM_INS_SWP: "swp",
    ARM_INS_SWPB: "swpb",
    ARM_INS_SXTAB: "sxtab",
    ARM_INS_SXTAB16: "sxtab16",
    ARM_INS_SXTAH: "sxtah",
    ARM_INS_SXTB: "sxtb",
    ARM_INS_SXTB16: "sxtb16",
    ARM_INS_SXTH: "sxth",
    ARM_INS_TEQ: "teq",
    ARM_INS_TRAP: "trap",
    ARM_INS_TST: "tst",
    ARM_INS_UADD16: "uadd16",
    ARM_INS_UADD8: "uadd8",
    ARM_INS_UASX: "uasx",
    ARM_INS_UBFX: "ubfx",
    ARM_INS_UDF: "udf",
    ARM_INS_UDIV: "udiv",
    ARM_INS_UHADD16: "uhadd16",
    ARM_INS_UHADD8: "uhadd8",
    ARM_INS_UHASX: "uhasx",
    ARM_INS_UHSAX: "uhsax",
    ARM_INS_UHSUB16: "uhsub16",
    ARM_INS_UHSUB8: "uhsub8",
    ARM_INS_UMAAL: "umaal",
    ARM_INS_UMLAL: "umlal",
    ARM_INS_UMULL: "umull",
    ARM_INS_UQADD16: "uqadd16",
    ARM_INS_UQADD8: "uqadd8",
    ARM_INS_UQASX: "uqasx",
    ARM_INS_UQSAX: "uqsax",
    ARM_INS_UQSUB16: "uqsub16",
    ARM_INS_UQSUB8: "uqsub8",
    ARM_INS_USAD8: "usad8",
    ARM_INS_USADA8: "usada8",
    ARM_INS_USAT: "usat",
    ARM_INS_USAT16: "usat16",
    ARM_INS_USAX: "usax",
    ARM_INS_USUB16: "usub16",
    ARM_INS_USUB8: "usub8",
    ARM_INS_UXTAB: "uxtab",
    ARM_INS_UXTAB16: "uxtab16",
    ARM_INS_UXTAH: "uxtah",
    ARM_INS_UXTB: "uxtb",
    ARM_INS_UXTB16: "uxtb16",
    ARM_INS_UXTH: "uxth",
    ARM_INS_VABAL: "vabal",
    ARM_INS_VABA: "vaba",
    ARM_INS_VABDL: "vabdl",
    ARM_INS_VABD: "vabd",
    ARM_INS_VABS: "vabs",
    ARM_INS_VACGE: "vacge",
    ARM_INS_VACGT: "vacgt",
    ARM_INS_VADD: "vadd",
    ARM_INS_VADDHN: "vaddhn",
    ARM_INS_VADDL: "vaddl",
    ARM_INS_VADDW: "vaddw",
    ARM_INS_VAND: "vand",
    ARM_INS_VBIC: "vbic",
    ARM_INS_VBIF: "vbif",
    ARM_INS_VBIT: "vbit",
    ARM_INS_VBSL: "vbsl",
    ARM_INS_VCEQ: "vceq",
    ARM_INS_VCGE: "vcge",
    ARM_INS_VCGT: "vcgt",
    ARM_INS_VCLE: "vcle",
    ARM_INS_VCLS: "vcls",
    ARM_INS_VCLT: "vclt",
    ARM_INS_VCLZ: "vclz",
    ARM_INS_VCMP: "vcmp",
    ARM_INS_VCMPE: "vcmpe",
    ARM_INS_VCNT: "vcnt",
    ARM_INS_VCVTA: "vcvta",
    ARM_INS_VCVTB: "vcvtb",
    ARM_INS_VCVT: "vcvt",
    ARM_INS_VCVTM: "vcvtm",
    ARM_INS_VCVTN: "vcvtn",
    ARM_INS_VCVTP: "vcvtp",
    ARM_INS_VCVTT: "vcvtt",
    ARM_INS_VDIV: "vdiv",
    ARM_INS_VDUP: "vdup",
    ARM_INS_VEOR: "veor",
    ARM_INS_VEXT: "vext",
    ARM_INS_VFMA: "vfma",
    ARM_INS_VFMS: "vfms",
    ARM_INS_VFNMA: "vfnma",
    ARM_INS_VFNMS: "vfnms",
    ARM_INS_VHADD: "vhadd",
    ARM_INS_VHSUB: "vhsub",
    ARM_INS_VLD1: "vld1",
    ARM_INS_VLD2: "vld2",
    ARM_INS_VLD3: "vld3",
    ARM_INS_VLD4: "vld4",
    ARM_INS_VLDMDB: "vldmdb",
    ARM_INS_VLDMIA: "vldmia",
    ARM_INS_VLDR: "vldr",
    ARM_INS_VMAXNM: "vmaxnm",
    ARM_INS_VMAX: "vmax",
    ARM_INS_VMINNM: "vminnm",
    ARM_INS_VMIN: "vmin",
    ARM_INS_VMLA: "vmla",
    ARM_INS_VMLAL: "vmlal",
    ARM_INS_VMLS: "vmls",
    ARM_INS_VMLSL: "vmlsl",
    ARM_INS_VMOVL: "vmovl",
    ARM_INS_VMOVN: "vmovn",
    ARM_INS_VMSR: "vmsr",
    ARM_INS_VMUL: "vmul",
    ARM_INS_VMULL: "vmull",
    ARM_INS_VMVN: "vmvn",
    ARM_INS_VNEG: "vneg",
    ARM_INS_VNMLA: "vnmla",
    ARM_INS_VNMLS: "vnmls",
    ARM_INS_VNMUL: "vnmul",
    ARM_INS_VORN: "vorn",
    ARM_INS_VORR: "vorr",
    ARM_INS_VPADAL: "vpadal",
    ARM_INS_VPADDL: "vpaddl",
    ARM_INS_VPADD: "vpadd",
    ARM_INS_VPMAX: "vpmax",
    ARM_INS_VPMIN: "vpmin",
    ARM_INS_VQABS: "vqabs",
    ARM_INS_VQADD: "vqadd",
    ARM_INS_VQDMLAL: "vqdmlal",
    ARM_INS_VQDMLSL: "vqdmlsl",
    ARM_INS_VQDMULH: "vqdmulh",
    ARM_INS_VQDMULL: "vqdmull",
    ARM_INS_VQMOVUN: "vqmovun",
    ARM_INS_VQMOVN: "vqmovn",
    ARM_INS_VQNEG: "vqneg",
    ARM_INS_VQRDMULH: "vqrdmulh",
    ARM_INS_VQRSHL: "vqrshl",
    ARM_INS_VQRSHRN: "vqrshrn",
    ARM_INS_VQRSHRUN: "vqrshrun",
    ARM_INS_VQSHL: "vqshl",
    ARM_INS_VQSHLU: "vqshlu",
    ARM_INS_VQSHRN: "vqshrn",
    ARM_INS_VQSHRUN: "vqshrun",
    ARM_INS_VQSUB: "vqsub",
    ARM_INS_VRADDHN: "vraddhn",
    ARM_INS_VRECPE: "vrecpe",
    ARM_INS_VRECPS: "vrecps",
    ARM_INS_VREV16: "vrev16",
    ARM_INS_VREV32: "vrev32",
    ARM_INS_VREV64: "vrev64",
    ARM_INS_VRHADD: "vrhadd",
    ARM_INS_VRINTA: "vrinta",
    ARM_INS_VRINTM: "vrintm",
    ARM_INS_VRINTN: "vrintn",
    ARM_INS_VRINTP: "vrintp",
    ARM_INS_VRINTR: "vrintr",
    ARM_INS_VRINTX: "vrintx",
    ARM_INS_VRINTZ: "vrintz",
    ARM_INS_VRSHL: "vrshl",
    ARM_INS_VRSHRN: "vrshrn",
    ARM_INS_VRSHR: "vrshr",
    ARM_INS_VRSQRTE: "vrsqrte",
    ARM_INS_VRSQRTS: "vrsqrts",
    ARM_INS_VRSRA: "vrsra",
    ARM_INS_VRSUBHN: "vrsubhn",
    ARM_INS_VSELEQ: "vseleq",
    ARM_INS_VSELGE: "vselge",
    ARM_INS_VSELGT: "vselgt",
    ARM_INS_VSELVS: "vselvs",
    ARM_INS_VSHLL: "vshll",
    ARM_INS_VSHL: "vshl",
    ARM_INS_VSHRN: "vshrn",
    ARM_INS_VSHR: "vshr",
    ARM_INS_VSLI: "vsli",
    ARM_INS_VSQRT: "vsqrt",
    ARM_INS_VSRA: "vsra",
    ARM_INS_VSRI: "vsri",
    ARM_INS_VST1: "vst1",
    ARM_INS_VST2: "vst2",
    ARM_INS_VST3: "vst3",
    ARM_INS_VST4: "vst4",
    ARM_INS_VSTMDB: "vstmdb",
    ARM_INS_VSTMIA: "vstmia",
    ARM_INS_VSTR: "vstr",
    ARM_INS_VSUB: "vsub",
    ARM_INS_VSUBHN: "vsubhn",
    ARM_INS_VSUBL: "vsubl",
    ARM_INS_VSUBW: "vsubw",
    ARM_INS_VSWP: "vswp",
    ARM_INS_VTBL: "vtbl",
    ARM_INS_VTBX: "vtbx",
    ARM_INS_VCVTR: "vcvtr",
    ARM_INS_VTRN: "vtrn",
    ARM_INS_VTST: "vtst",
    ARM_INS_VUZP: "vuzp",
    ARM_INS_VZIP: "vzip",
    ARM_INS_ADDW: "addw",
    ARM_INS_ASR: "asr",
    ARM_INS_DCPS1: "dcps1",
    ARM_INS_DCPS2: "dcps2",
    ARM_INS_DCPS3: "dcps3",
    ARM_INS_IT: "it",
    ARM_INS_LSL: "lsl",
    ARM_INS_LSR: "lsr",
    ARM_INS_ORN: "orn",
    ARM_INS_ROR: "ror",
    ARM_INS_RRX: "rrx",
    ARM_INS_SUBW: "subw",
    ARM_INS_TBB: "tbb",
    ARM_INS_TBH: "tbh",
    ARM_INS_CBNZ: "cbnz",
    ARM_INS_CBZ: "cbz",
    ARM_INS_POP: "pop",
    ARM_INS_PUSH: "push",
    ARM_INS_NOP: "nop",
    ARM_INS_YIELD: "yield",
    ARM_INS_WFE: "wfe",
    ARM_INS_WFI: "wfi",
    ARM_INS_SEV: "sev",
    ARM_INS_SEVL: "sevl",
    ARM_INS_VPUSH: "vpush",
    ARM_INS_VPOP: "vpop",
    ARM_INS_ENDING: "ending",
}

# disassembler definitions
THUMB_DISASSEMBLER = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
THUMB_DISASSEMBLER.detail = True
ARM_DISASSEMBLER = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
ARM_DISASSEMBLER.detail = True

# constants
BRANCH_IDS = (ARM_INS_BX, ARM_INS_B)
COND_BRANCH_IDS = (ARM_INS_CBNZ, ARM_INS_CBZ)
CALL_IDS = (ARM_INS_BL, ARM_INS_BLX)


class Function:
    def __init__(self, block_tree: IntervalTree, name="sub"):
        if len(block_tree) == 0:
            raise ValueError("Cannot create function from empty block tree")
        self.name = name
        blocks = [iv.data for iv in block_tree]
        self.function_blocks = sorted(blocks, key=lambda x: x.start_addr)
        self.start_addr = self.function_blocks[0].start_addr
        self.stop_addr = self.function_blocks[-1].stop_addr
        self.instructions = 0
        self.pushed_registers = 0
        self.popped_registers = 0
        self.gaps = []
        self.branches = 0
        self.conditional_branches = 0
        self.calls = set()
        last_block_end = self.function_blocks[0].stop_addr
        for block in self.function_blocks:
            if last_block_end < block.start_addr:
                self.gaps.append((last_block_end, block.start_addr))
            last_block_end = block.stop_addr
            self.instructions += block.instructions
            self.pushed_registers += block.pushed_registers
            self.popped_registers += block.popped_registers
            self.calls = self.calls.union(block.calls)
            self.branches += block.branches
            self.conditional_branches += block.conditional_branches

    def __str__(self):
        call_str = ", ".join(f"0x{call:X}" for call in self.calls)
        gap_str = ", ".join(f"0x{x:X} - 0x{y:X}" for x, y in self.gaps)
        # block_str = ",\n".join(str(block) for block in self.function_blocks)
        return f"Fnc {self.name} 0x{self.start_addr:X}-0x{self.stop_addr:X} - inst: {self.instructions}, \n\
                \tpushed regs : {self.pushed_registers}, popped regs: {self.popped_registers}, \n\
                \tcalls: {call_str}, \ngaps: {gap_str}"  # \nblocks:\n{block_str}"


@dataclass
class FunctionBlock:
    """
    Information representing one block of code
    Defintion: block of code - here - the longest sequence of code that can
    be executed without branching.
    """

    start_addr: int = 0
    stop_addr: int = 0
    instructions: int = 0
    calls: Set = field(default_factory=set)
    branches: int = 0
    conditional_branches: int = 0
    pushed_registers: int = 0
    popped_registers: int = 0

    def __add__(self, other: "FunctionBlock"):
        return FunctionBlock(
            min(self.start_addr, other.start_addr),
            max(self.stop_addr, other.stop_addr),
            self.instructions + other.instructions,
            self.calls.union(other.calls),
            self.branches + other.branches,
            self.conditional_branches + other.conditional_branches,
            self.pushed_registers + other.pushed_registers,
            self.popped_registers + other.popped_registers,
        )

    def __str__(self):
        call_str = ", ".join(f"0x{call:X}" for call in self.calls)
        return f"blk 0x{self.start_addr:X}-0x{self.stop_addr:X} - inst: {self.instructions}, \n\
                \tpushed regs : {self.pushed_registers}, popped regs: {self.popped_registers}, \n\
                \tcalls: {call_str}"


def parse_imm(immediate):
    x = struct.pack(">i", immediate)
    while x[0] in ("\0", 0):
        x = x[1:]
    return int.from_bytes(x, byteorder="big", signed=False)


def sweep_function(binary, start, addr_stack):
    block_tree = IntervalTree()
    branch_stack = [start]
    heapify(branch_stack)
    while branch_stack:
        addr = heappop(branch_stack)
        part = FunctionBlock(start_addr=addr)
        for inst in THUMB_DISASSEMBLER.disasm(binary[addr:], addr):
            i_addr = inst.address
            if block_tree.overlaps(i_addr):
                # we already visited this address (maybe a loop?)
                break
            part.instructions += 1
            part.stop_addr = i_addr + inst.size
            ops = len(inst.operands)
            reg_reads, reg_writes = inst.regs_access()
            if inst.id in BRANCH_IDS:
                if ARM_REG_LR in reg_reads:
                    if inst.cc == ARM_CC_AL:
                        # this is a conditional return
                        continue
                    # this is a unconditional return
                    break
                new_addr = parse_imm(inst.operands[0].imm)
                heappush(branch_stack, new_addr)
                if inst.cc == ARM_CC_AL:
                    part.branches += 1
                    break
                else:
                    part.conditional_branches += 1
            elif ops == 1 and inst.id in CALL_IDS:
                new_addr = parse_imm(inst.operands[0].imm)
                addr_stack.add(new_addr)
                part.calls.add(new_addr)
            elif ops == 2 and inst.id in COND_BRANCH_IDS:
                new_addr = parse_imm(inst.operands[1].imm)
                heappush(branch_stack, new_addr)
                part.conditional_branches += 1
            elif ARM_REG_PC in reg_writes:
                # assume return for any otherwise unmatched changes of PC
                break
        if part.start_addr < part.stop_addr:
            block_tree[part.start_addr : part.stop_addr] = part
    block_tree.merge_overlaps(add)
    return block_tree


def sweep(binary, start_addresses: List[int], region_store=None):
    addr_validator = lambda x: True
    if type(binary) is not bytes:
        data = bytes(binary.read())
        addr_validator = binary.addr_is_valid
    if region_store is None:
        region_store = IntervalTree()
    addr_stack = set(start_addresses)
    while addr_stack:
        addr = addr_stack.pop()
        if region_store.overlaps(addr) or not addr_validator(addr):
            continue
        function_parts = sweep_function(data, addr, addr_stack)
        if function_parts:
            fnc = Function(function_parts)
            yield fnc
            region_store |= function_parts


if __name__ == "__main__":
    data = None
    start = 0x58008
    with open("./20735B1.bin", "rb") as bin_:
        data = bin_.read()
    for i, fnc in enumerate(sweep(data, [start])):
        print(i, fnc)
