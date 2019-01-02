#include <Python.h>

#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

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

inline static u64 be64(u64 var) {
    if(endian.islittle) {
        #if defined __clang__ || defined __GNUC__
        var = __builtin_bswap64(var);
        #elif defined _MSC_VER
        var = _byteswap_uint64(var);
        #else
        u64 tmp = var;
        ((u8 *) &var)[7] = ((u8 *) &tmp)[0];
        ((u8 *) &var)[6] = ((u8 *) &tmp)[1];
        ((u8 *) &var)[5] = ((u8 *) &tmp)[2];
        ((u8 *) &var)[4] = ((u8 *) &tmp)[3];
        ((u8 *) &var)[3] = ((u8 *) &tmp)[4];
        ((u8 *) &var)[2] = ((u8 *) &tmp)[5];
        ((u8 *) &var)[1] = ((u8 *) &tmp)[6];
        ((u8 *) &var)[0] = ((u8 *) &tmp)[7];
        #endif
    }
    return var;
}

inline static u64 le64(u64 var) {
    if(!endian.islittle) {
        #if defined __clang__ || defined __GNUC__
        var = __builtin_bswap64(var);
        #elif defined _MSC_VER
        var = _byteswap_uint64(var);
        #else
        //sacrifice code size for possible speed up
        u64 tmp = var;
        ((u8 *) &var)[7] = ((u8 *) &tmp)[0];
        ((u8 *) &var)[6] = ((u8 *) &tmp)[1];
        ((u8 *) &var)[5] = ((u8 *) &tmp)[2];
        ((u8 *) &var)[4] = ((u8 *) &tmp)[3];
        ((u8 *) &var)[3] = ((u8 *) &tmp)[4];
        ((u8 *) &var)[2] = ((u8 *) &tmp)[5];
        ((u8 *) &var)[1] = ((u8 *) &tmp)[6];
        ((u8 *) &var)[0] = ((u8 *) &tmp)[7];
        #endif
    }
    return var;
}

inline static union bigint128 geniv(u64 *pos) {
    union bigint128 out;
    out.value64[1] = be64(pos[0]);
    out.value64[0] = be64(pos[1]);
    return out;
}

inline static void xor128(u64 *foo, u64 *bar) {
    foo[0] ^= bar[0];
    foo[1] ^= bar[1];
}

inline static void shift128(u64 *foo) {
    //with little endian order, we can do this
    foo[1] = le64(le64(foo[1]) << 1) | (le64(foo[0]) >> 63);
    foo[0] = le64(le64(foo[0]) << 1);
}

inline static void
aes_xtsn_schedule_128(u8* key, u8* tweakin, u8* roundkeys_x2) {
    aes_key_schedule_128(key, roundkeys_x2);
    aes_key_schedule_128(tweakin, roundkeys_x2 + 0xB0);
}

void
aes_xtsn_decrypt(u8 *buffer, u64 len, u8 *roundkeys_x2, u64 sectoroffsethi, u64 sectoroffsetlo, u32 sector_size) {
    u64 i;
    u8 *roundkeys_key = roundkeys_x2;
    u8 *roundkeys_tweak = roundkeys_x2 + 0xB0;
    u64 position[2] = {sectoroffsetlo, sectoroffsethi};

    for (i = 0; i < (len / (u64) sector_size); i++) {
        union bigint128 tweak = geniv(position);
        aes_encrypt_128(roundkeys_tweak, tweak.value8, tweak.value8);
        unsigned int j;
        for (j = 0; j < sector_size / 16; j++) {
            xor128((u64 *) buffer, tweak.value64);
            aes_decrypt_128(roundkeys_key, buffer, buffer);
            xor128((u64 *) buffer, tweak.value64);
            int flag = tweak.value8[15] & 0x80;
            shift128(tweak.value64);
            if (flag) tweak.value8[0] ^= 0x87;
            buffer += 16;
        }
        if (position[0] > (position[0] + 1LLU)) position[1] += 1LLU; //if overflow, we gotta
        position[0] += 1LLU;
    }
    u64 remain_len = (len % (u64) sector_size);
    if(remain_len) {
        union bigint128 tweak = geniv(position);
        u64 j;
        aes_encrypt_128(roundkeys_tweak, tweak.value8, tweak.value8);
        for (j = 0; j < remain_len / 16LLU; j++) {
            xor128((u64 *) buffer, tweak.value64);
            aes_decrypt_128(roundkeys_key, buffer, buffer);
            xor128((u64 *) buffer, tweak.value64);
            int flag = tweak.value8[15] & 0x80;
            shift128(tweak.value64);
            if (flag) tweak.value8[0] ^= 0x87;
            buffer += 16;
        }
    }
}

void
aes_xtsn_encrypt(u8 *buffer, u64 len, u8 *roundkeys_x2, u64 sectoroffsethi, u64 sectoroffsetlo, u32 sector_size) {
    u64 i;
    u8 *roundkeys_key = roundkeys_x2;
    u8 *roundkeys_tweak = roundkeys_x2 + 0xB0;
    u64 position[2] = {sectoroffsetlo, sectoroffsethi};

    for (i = 0; i < (len / (u64) sector_size); i++) {
        union bigint128 tweak = geniv(position);
        aes_encrypt_128(roundkeys_tweak, tweak.value8, tweak.value8);
        unsigned int j;
        for (j = 0; j < sector_size / 16; j++) {
            xor128((u64 *) buffer, tweak.value64);
            aes_encrypt_128(roundkeys_key, buffer, buffer);
            xor128((u64 *) buffer, tweak.value64);
            int flag = tweak.value8[15] & 0x80;
            shift128(tweak.value64);
            if (flag) tweak.value8[0] ^= 0x87;
            buffer += 16;
        }
        if (position[0] > (position[0] + 1LLU)) position[1] += 1LLU; //if overflow, we gotta
        position[0] += 1LLU;
    }
    u64 remain_len = (len % (u64) sector_size);
    if(remain_len) {
        union bigint128 tweak = geniv(position);
        u64 j;
        aes_encrypt_128(roundkeys_tweak, tweak.value8, tweak.value8);
        for (j = 0; j < remain_len / 16LLU; j++) {
            xor128((u64 *) buffer, tweak.value64);
            aes_encrypt_128(roundkeys_key, buffer, buffer);
            xor128((u64 *) buffer, tweak.value64);
            int flag = tweak.value8[15] & 0x80;
            shift128(tweak.value64);
            if (flag) tweak.value8[0] ^= 0x87;
            buffer += 16;
        }
    }
}

// python stuff
static PyObject *py_xtsn_schedule(PyObject *self, PyObject *args) {
    Py_buffer key, tweak;
    PyObject *buf = NULL;

    if (!PyArg_ParseTuple(args, "y*y*", &key, &tweak)) {
        return NULL;
    }

    if (key.len != 16) {
        PyErr_SetString(PyExc_ValueError, "key len is not 16");
        goto fail;
    }

    if (tweak.len != 16) {
        PyErr_SetString(PyExc_ValueError, "tweak len is not 16");
        goto fail;
    }

    u8 roundkeys_x2[0xB0 * 2] = {0};
    aes_xtsn_schedule_128(key.buf, tweak.buf, roundkeys_x2);
    buf = PyBytes_FromStringAndSize((char * ) roundkeys_x2, 0xB0 * 2);

    if (!buf) {
        PyErr_SetString(PyExc_MemoryError, "Python doesn't have memory for the buffer.");
    }

fail:
    PyBuffer_Release(&key);
    PyBuffer_Release(&tweak);
    return buf;
}

static PyObject *py_xtsn_decrypt(PyObject *self, PyObject *args) {
    Py_buffer orig_buf, roundkeys_x2;
    unsigned long long sectoroffsethi, sectoroffsetlo;
    u32 sector_size;
    PyObject *buf = NULL;

    if (!PyArg_ParseTuple(args, "y*y*KKk", &orig_buf, &roundkeys_x2, &sectoroffsethi, &sectoroffsetlo, &sector_size))
        return NULL;

    if (roundkeys_x2.len != 0xB0 * 2) {
        PyErr_SetString(PyExc_ValueError, "roundkeys_x2 len is not 16");
        goto fail;
    }

    if (orig_buf.len % 16) {
        PyErr_SetString(PyExc_ValueError, "length not divisable by 16");
        goto fail;
    }

    if (sector_size % 16) {
        PyErr_SetString(PyExc_ValueError, "sector size not divisable by 16");
        goto fail;
    }

    buf = PyBytes_FromStringAndSize(orig_buf.buf, orig_buf.len);

    if (!buf) {
        PyErr_SetString(PyExc_MemoryError, "Python doesn't have memory for the buffer.");
        goto fail;
    }

    aes_xtsn_decrypt((u8 *) PyBytes_AsString(buf), (u64) orig_buf.len, roundkeys_x2.buf, sectoroffsethi,
                     sectoroffsetlo, sector_size);

fail:
    PyBuffer_Release(&orig_buf);
    PyBuffer_Release(&roundkeys_x2);
    return buf;
}

static PyObject *py_xtsn_encrypt(PyObject *self, PyObject *args) {
    Py_buffer orig_buf, roundkeys_x2;
    unsigned long long sectoroffsethi, sectoroffsetlo;
    u32 sector_size;
    PyObject *buf = NULL;

    if (!PyArg_ParseTuple(args, "y*y*KKk", &orig_buf, &roundkeys_x2, &sectoroffsethi, &sectoroffsetlo, &sector_size))
        return NULL;

    if (roundkeys_x2.len != 0xB0 * 2) {
        PyErr_SetString(PyExc_ValueError, "roundkeys_x2 len is not 16");
        goto fail;
    }

    if (orig_buf.len % 16) {
        PyErr_SetString(PyExc_ValueError, "length not divisable by 16");
        goto fail;
    }

    if (sector_size % 16) {
        PyErr_SetString(PyExc_ValueError, "sector size not divisable by 16");
        goto fail;
    }

    buf = PyBytes_FromStringAndSize(orig_buf.buf, orig_buf.len);

    if (!buf) {
        PyErr_SetString(PyExc_MemoryError, "Python doesn't have memory for the buffer.");
        goto fail;
    }

    aes_xtsn_encrypt((u8 *) PyBytes_AsString(buf), (u64) orig_buf.len, roundkeys_x2.buf, sectoroffsethi,
                     sectoroffsetlo, sector_size);

fail:
    PyBuffer_Release(&orig_buf);
    PyBuffer_Release(&roundkeys_x2);
    return buf;
}

static PyMethodDef ccrypto_methods[] = {
    {"_xtsn_schedule", py_xtsn_schedule, METH_VARARGS, NULL},
    {"_xtsn_decrypt",  py_xtsn_decrypt,  METH_VARARGS, NULL},
    {"_xtsn_encrypt",  py_xtsn_encrypt,  METH_VARARGS, NULL},
    {NULL,             NULL,             0,            NULL}
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
