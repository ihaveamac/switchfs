#include <Python.h>

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define ECB 1
#define CBC 0
#define CTR 0

#include "aes.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

union {
    u16 foo;
    u8 islittle;
} endian = {.foo = 1};

union bigint128 {
    u8 value8[16];
    u64 value64[2];
};

inline static union bigint128 geniv(u64 *pos) {
    union bigint128 out;
    if (endian.islittle) {
        u8 *foo = (u8 *) pos;
        int i;
        for (i = 0; i < 16; i++) out.value8[15 - i] = foo[i];
    }
    else {
        out.value64[1] = pos[0];
        out.value64[0] = pos[1];
    }
    return out;
}

inline static void xor128(u64 *foo, u64 *bar) {
    foo[0] ^= bar[0];
    foo[1] ^= bar[1];
}

inline static void shift128(u8 *foo) {
    int i;
    for (i = 15; i >= 0; i--) {
        if (i != 0) foo[i] = (foo[i] << 1) | (foo[i - 1] >> 7);
        else foo[i] = (foo[i] << 1);
    }
}

void aes_xtsn_decrypt(u8 *buffer, u64 len, u8 *key, u8 *tweakin, u64 sectoroffsethi, u64 sectoroffsetlo, u32 sector_size) {
    u64 i;
    struct AES_ctx _key, _tweak;
    AES_init_ctx(&_key, key);
    AES_init_ctx(&_tweak, tweakin);
    u64 position[2] = {sectoroffsetlo, sectoroffsethi};

    for (i = 0; i < (len / (u64) sector_size); i++) {
        union bigint128 tweak = geniv(position);
        AES_ECB_encrypt(&_tweak, tweak.value8);
        int j;
        for (j = 0; j < sector_size / 16; j++) {
            xor128(buffer, tweak.value64);
            AES_ECB_decrypt(&_key, buffer);
            xor128(buffer, tweak.value64);
            bool flag = tweak.value8[15] & 0x80;
            shift128(tweak.value8);
            if (flag) tweak.value8[0] ^= 0x87;
            buffer += 16;
        }
        if (position[0] > (position[0] + 1LLU)) position[1] += 1LLU; //if overflow, we gotta
        position[0] += 1LLU;
    }
}

// python stuff
static PyObject *py_xtsn_decrypt(PyObject *self, PyObject *args) {
    Py_buffer orig_buf, key, tweak;
    unsigned long long sectoroffsethi, sectoroffsetlo;
    u32 sector_size;

    if (!PyArg_ParseTuple(args, "y*y*y*KKk", &orig_buf, &key, &tweak, &sectoroffsethi, &sectoroffsetlo, &sector_size))
        return NULL;

    if (key.len != 16) {
        PyErr_SetString(PyExc_ValueError, "key len is not 16");
        return NULL;
    }

    if (tweak.len != 16) {
        PyErr_SetString(PyExc_ValueError, "tweak len is not 16");
        return NULL;
    }

    PyObject *buf = PyBytes_FromStringAndSize(orig_buf.buf, orig_buf.len);

    aes_xtsn_decrypt(PyBytes_AsString(buf), orig_buf.len, key.buf, tweak.buf, sectoroffsethi, sectoroffsetlo, sector_size);

    PyBuffer_Release(&orig_buf);
    PyBuffer_Release(&key);
    PyBuffer_Release(&tweak);

    return buf;
}

static PyMethodDef ccrypto_methods[] = {
    {"_xtsn_decrypt", py_xtsn_decrypt, METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef ccrypto_module = {
    PyModuleDef_HEAD_INIT,
    "ccrypto",
    NULL,
    -1,
    ccrypto_methods
};

PyMODINIT_FUNC PyInit_ccrypto(void) {
    return PyModule_Create(&ccrypto_module);
}
