#include <Python.h>

#include <cstdio>
#include <inttypes.h>

extern "C" {
#include "aes.h"
}

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

const static union {
    u16 foo;
    u8 islittle;
} endian = {(u16)0x001};

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

class bigint128 {
public:
    union {
        u8 v8[16];
        u64 v64[2];
    };
};

class SectorOffset : public bigint128 {
public:
    inline u64* Lo() {return &v64[0];}
    inline u64* Hi() {return &v64[1];}
    inline void Step() {
        if (v64[0] > (v64[0] + 1LLU)) v64[1] += 1LLU;
        v64[0] += 1LLU;
    }
    inline void Step(u64 amount) {
        if (v64[0] > (v64[0] + amount)) v64[1] += 1LLU;
        v64[0] += amount;
    }
};

class Tweak : public bigint128 {
public:
    inline Tweak(SectorOffset& offset, u8 *roundkeys_tweak) {
        v64[1] = be64(offset.v64[0]);
        v64[0] = be64(offset.v64[1]);
        aes_encrypt_128(roundkeys_tweak, v8, v8);
    }
    inline void Update() {
        int flag = v8[15] & 0x80;
        v64[1] = le64(le64(v64[1]) << 1) | (le64(v64[0]) >> 63);
        v64[0] = le64(le64(v64[0]) << 1);
        if (flag) v8[0] ^= 0x87;
    }
};

class Buffer {
public:
    bigint128* ptr;
    u64 len;
    inline Buffer& operator^=(Tweak& tweak) {
        ptr->v64[0] ^= tweak.v64[0];
        ptr->v64[1] ^= tweak.v64[1];
        return *this;
    }
    inline void Step() {
        ptr++;
        len -= 16LLU;
    }
};

template<void (*crypher)(const u8 *, const u8 *, u8 *)>
class XTSN {
    SectorOffset sectoroffset;
    Buffer buf;
    u64 sector_size;
    u64 skipped_bytes;
    u8 *roundkeys_key;
    u8 *roundkeys_tweak;
    #ifdef DEBUGON
    void Debug() { //debug printing.
        printf("Sector Offset (Lo, Hi): %llu, %llu\n"
            "Buffer Length: %llu\n"
            "Sector Size: %llu\n"
            "Skipped Bytes: %llu\n\n",
            (unsigned long long)*sectoroffset.Lo(), (unsigned long long)*sectoroffset.Hi(),
            (unsigned long long)buf.len,
            (unsigned long long)sector_size,
            (unsigned long long)skipped_bytes);
        fflush(stdout);
    }
    #endif
    void Run() {
        if(skipped_bytes) {
            if(skipped_bytes / sector_size) {
                sectoroffset.Step(skipped_bytes / sector_size);
                skipped_bytes %= sector_size;
            }
            if(skipped_bytes) {
                Tweak tweak(sectoroffset, roundkeys_tweak);
                u64 i;
                for (i = 0; i < (skipped_bytes / 16LLU); i++) {
                    tweak.Update();
                }
                for (i = 0; i < ((sector_size - skipped_bytes) / 16LLU) && buf.len; i++) {
                    buf ^= tweak;
                    crypher(roundkeys_key, buf.ptr->v8, buf.ptr->v8);
                    buf ^= tweak;
                    tweak.Update();
                    buf.Step();
                }
                sectoroffset.Step();
            }
        }
        while(buf.len) {
            Tweak tweak(sectoroffset, roundkeys_tweak);
            u64 i;
            for (i = 0; i < (sector_size / 16LLU) && buf.len; i++) {
                buf ^= tweak;
                crypher(roundkeys_key, buf.ptr->v8, buf.ptr->v8);
                buf ^= tweak;
                tweak.Update();
                buf.Step();
            }
            sectoroffset.Step();
        }
    }
public:
    inline PyObject *PythonRun(PyObject *self, PyObject *args) {
        Py_buffer orig_buf, roundkeys_x2;
        PyObject *local_buf = NULL;

        if (!PyArg_ParseTuple(args, "y*y*KKKK", &orig_buf, &roundkeys_x2,
           sectoroffset.Hi(), sectoroffset.Lo(), &sector_size, &skipped_bytes))
            return NULL;

        if (orig_buf.len == 0) { //nothing to crypt i guess
            local_buf = PyBytes_FromStringAndSize((char * ) NULL, 0);
            if (!local_buf) {
                PyErr_SetString(PyExc_MemoryError, "Python doesn't have memory for the buffer.");
            }
            goto end;
        }

        if (roundkeys_x2.len != 0xB0 * 2) {
            PyErr_SetString(PyExc_ValueError, "roundkeys_x2 len is not 352");
            goto end;
        }

        if (orig_buf.len % 16) {
            PyErr_SetString(PyExc_ValueError, "length not divisable by 16");
            goto end;
        }

        if (skipped_bytes % 16) {
            PyErr_SetString(PyExc_ValueError, "skipped bytes not divisable by 16");
            goto end;
        }

        if (sector_size % 16 || sector_size == 0) {
            PyErr_SetString(PyExc_ValueError, sector_size == 0 ? "sector size must not be 0" : "sector size not divisable by 16");
            goto end;
        }

        local_buf = PyBytes_FromStringAndSize((char * ) orig_buf.buf, orig_buf.len);

        if (!local_buf) {
            PyErr_SetString(PyExc_MemoryError, "Python doesn't have memory for the buffer.");
            goto end;
        }

        roundkeys_key = (u8*)roundkeys_x2.buf;
        roundkeys_tweak = (u8*)roundkeys_x2.buf + 0xB0;
        buf.ptr = (bigint128 *) PyBytes_AsString(local_buf);
        buf.len = (u64) orig_buf.len;

        #ifdef DEBUGON
        Debug();
        #endif
        Run();

    end:
        PyBuffer_Release(&orig_buf);
        PyBuffer_Release(&roundkeys_x2);
        return local_buf;
    }
};

typedef XTSN<&aes_decrypt_128> XTSNDecrypt;
typedef XTSN<&aes_encrypt_128> XTSNEncrypt;

inline static void
aes_xtsn_schedule_128(u8* key, u8* tweakin, u8* roundkeys_x2) {
    aes_key_schedule_128(key, roundkeys_x2);
    aes_key_schedule_128(tweakin, roundkeys_x2 + 0xB0);
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
        goto end;
    }

    if (tweak.len != 16) {
        PyErr_SetString(PyExc_ValueError, "tweak len is not 16");
        goto end;
    }

    u8 roundkeys_x2[0xB0 * 2];
    aes_xtsn_schedule_128((u8*)key.buf, (u8*)tweak.buf, roundkeys_x2);
    buf = PyBytes_FromStringAndSize((char * ) roundkeys_x2, 0xB0 * 2);

    if (!buf) {
        PyErr_SetString(PyExc_MemoryError, "Python doesn't have memory for the buffer.");
    }

end:
    PyBuffer_Release(&key);
    PyBuffer_Release(&tweak);
    return buf;
}

static PyObject *py_xtsn_decrypt(PyObject *self, PyObject *args) {
    XTSNDecrypt xtsn;
    return xtsn.PythonRun(self, args);
}

static PyObject *py_xtsn_encrypt(PyObject *self, PyObject *args) {
    XTSNEncrypt xtsn;
    return xtsn.PythonRun(self, args);
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
