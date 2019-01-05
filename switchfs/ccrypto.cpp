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

typedef struct {
    PyObject_HEAD
    u8 roundkeys_x2[352];
} XTSNObject;

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
    static int FromPyLong(PyObject *o, SectorOffset *p) {
        if(!PyLong_CheckExact(o)) {
            PyErr_SetString(PyExc_ValueError, "Not an int was given, convertion to sector offset failed.");
            return 0;
        }
        auto buf = PyObject_CallMethod(o, "to_bytes", "is", 16, "big");
        if(!buf) return 0;
        u64 *_buf = (u64 *)PyBytes_AsString(buf);
        *p->Hi() = be64(_buf[0]);
        *p->Lo() = be64(_buf[1]);
        Py_DECREF(buf);

        return Py_CLEANUP_SUPPORTED;
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
    inline PyObject *PythonRun(XTSNObject *self, PyObject *args, PyObject *kwds) {
        Py_buffer orig_buf;
        PyObject *local_buf = NULL;

        static const char* keywords[] = {
            "buf",
            "sector_off",
            "sector_size",
            "skipped_bytes",
            NULL,
        };

        if (!PyArg_ParseTupleAndKeywords(args, kwds, "y*O&|KK", (char**)keywords, &orig_buf,
           &SectorOffset::FromPyLong, &sectoroffset, &sector_size, &skipped_bytes))
            return NULL;

        if (orig_buf.len == 0) { //nothing to crypt i guess
            local_buf = PyBytes_FromStringAndSize((char * ) NULL, 0);
            if (!local_buf) {
                PyErr_SetString(PyExc_MemoryError, "Python doesn't have memory for the buffer.");
            }
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

        roundkeys_key = self->roundkeys_x2;
        roundkeys_tweak = self->roundkeys_x2 + 0xB0;
        buf.ptr = (bigint128 *) PyBytes_AsString(local_buf);
        buf.len = (u64) orig_buf.len;

        #ifdef DEBUGON
        Debug();
        #endif
        Run();

    end:
        PyBuffer_Release(&orig_buf);
        return local_buf;
    }
    inline XTSN() : sector_size(0x200), skipped_bytes(0) {}
};

typedef XTSN<&aes_decrypt_128> XTSNDecrypt;
typedef XTSN<&aes_encrypt_128> XTSNEncrypt;

inline static void
aes_xtsn_schedule_128(u8* key, u8* tweakin, u8* roundkeys_x2) {
    aes_key_schedule_128(key, roundkeys_x2);
    aes_key_schedule_128(tweakin, roundkeys_x2 + 0xB0);
}

// python stuff
static int XTSN_init(XTSNObject *self, PyObject *args, PyObject *kwds) {
    Py_buffer key, tweak;
    int ret = -1;

    static const char* keywords[] = {
        "crypt",
        "tweak",
        NULL,
    };

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "y*y*", (char**)keywords, &key, &tweak)) {
        return -1;
    }

    if (key.len != 16) {
        PyErr_SetString(PyExc_ValueError, "key len is not 16");
        goto end;
    }

    if (tweak.len != 16) {
        PyErr_SetString(PyExc_ValueError, "tweak len is not 16");
        goto end;
    }

    aes_xtsn_schedule_128((u8*)key.buf, (u8*)tweak.buf, self->roundkeys_x2);
    ret = 0;

end:
    PyBuffer_Release(&key);
    PyBuffer_Release(&tweak);
    return ret;
}

static PyObject *py_xtsn_decrypt(XTSNObject *self, PyObject *args, PyObject *kwds) {
    XTSNDecrypt xtsn;
    return xtsn.PythonRun(self, args, kwds);
}

static PyObject *py_xtsn_encrypt(XTSNObject *self, PyObject *args, PyObject *kwds) {
    XTSNEncrypt xtsn;
    return xtsn.PythonRun(self, args, kwds);
}

static PyMethodDef XTSN_methods[] = {
    {"decrypt", (PyCFunction) py_xtsn_decrypt, METH_VARARGS | METH_KEYWORDS, "Decrypt AES-XTSN content."},
    {"encrypt", (PyCFunction) py_xtsn_encrypt, METH_VARARGS | METH_KEYWORDS, "Encrypt AES-XTSN content."},
    {NULL}
};

static class XTSNType_PyTypeObject : public PyTypeObject {
public:
    XTSNType_PyTypeObject() : PyTypeObject({PyVarObject_HEAD_INIT(NULL, 0)}) {
        tp_name = "crypto.XTSN";
        tp_basicsize = sizeof(XTSNObject);
        tp_itemsize = 0;
        tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE;
        tp_doc = "Nintendo AES-XTSN";
        tp_methods = XTSN_methods;
        tp_init = (initproc) XTSN_init;
        tp_new = PyType_GenericNew;
    }
} XTSNType;

//last time i tried this format with MSVC, it failed-
/*
static PyTypeObject XTSNType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name = "crypto.XTSN",
    .tp_basicsize = sizeof(XTSNObject),
    .tp_itemsize = 0,
    .tp_flags = Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,
    .tp_doc = "Nintendo AES-XTSN",
    .tp_methods = XTSN_methods,
    .tp_init = (initproc) XTSN_init,
    .tp_new = PyType_GenericNew,
};*/

static struct PyModuleDef ccrypto_module = {
    PyModuleDef_HEAD_INIT,
    "ccrypto",
    NULL,
    -1,
    NULL,
};

PyMODINIT_FUNC PyInit_ccrypto(void) {
    PyObject *m;
    if (PyType_Ready(&XTSNType) < 0)
        return NULL;

    m = PyModule_Create(&ccrypto_module);
    if (m == NULL)
        return NULL;

    Py_INCREF(&XTSNType);
    PyModule_AddObject(m, "XTSN", (PyObject *) &XTSNType);
    return m;
}
