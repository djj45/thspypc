#define Py_LIMITED_API 0x030A0000
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <stdint.h>
#include <string.h>

#define MAX_BITRLE_OUTPUT ((Py_ssize_t)12000000)
#define MAX_TRANSPOSE_OUTPUT ((Py_ssize_t)64000000)

typedef struct {
    const unsigned char *src;
    Py_ssize_t size;
    Py_ssize_t pos;
    unsigned int current;
    int bits_left;
} BitReader;

static unsigned int
read_byte(BitReader *reader)
{
    if (reader->pos < reader->size) {
        return reader->src[reader->pos++];
    }
    return 0;
}

static unsigned int
read_bit(BitReader *reader)
{
    unsigned int value = reader->current & 0x80U;
    reader->current = (reader->current << 1) & 0xffU;
    reader->bits_left--;
    if (reader->bits_left == 0) {
        reader->current = read_byte(reader);
        reader->bits_left = 8;
    }
    return value;
}

static Py_ssize_t
declared_bitrle_size(const unsigned char *src, Py_ssize_t src_size)
{
    uint32_t value;
    if (src_size < 4) {
        return 0;
    }
    value = ((uint32_t)src[0] << 24) |
            ((uint32_t)src[1] << 16) |
            ((uint32_t)src[2] << 8) |
            (uint32_t)src[3];
    if (value == 0 || value > (uint32_t)MAX_BITRLE_OUTPUT) {
        return 0;
    }
    return (Py_ssize_t)value;
}

static void
decode_bitrle_into(
    const unsigned char *src,
    Py_ssize_t src_size,
    unsigned char *out,
    Py_ssize_t out_size)
{
    BitReader reader;
    Py_ssize_t out_pos = 0;

    reader.src = src;
    reader.size = src_size;
    reader.pos = 5;
    reader.current = src_size > 4 ? src[4] : 0;
    reader.bits_left = 8;

#define EMIT(value) do { \
    if (out_pos < out_size) { out[out_pos] = (unsigned char)(value); } \
    out_pos++; \
} while (0)

    while (out_pos < out_size) {
        unsigned int fill;
        unsigned int slot_m8;
        unsigned int slot_m18;
        unsigned int slot_pc;
        unsigned int b9;

        if (read_bit(&reader) == 0) {
            EMIT(read_byte(&reader));
            EMIT(read_byte(&reader));
            continue;
        }
        if (read_bit(&reader) == 0) {
            EMIT(read_byte(&reader));
        }
        fill = read_bit(&reader) != 0 ? 0xffU : 0x00U;
        EMIT(fill);
        if (out_pos >= out_size) break;
        if (read_bit(&reader) == 0) continue;
        EMIT(fill);
        if (out_pos >= out_size) break;

        slot_m8 = read_bit(&reader);
        slot_m18 = read_bit(&reader);
        if (slot_m8 == 0) {
            if (slot_m18 != 0) EMIT(fill);
            continue;
        }
        EMIT(fill);
        EMIT(fill);
        if (out_pos >= out_size) break;
        if (slot_m18 == 0) continue;
        EMIT(fill);
        if (out_pos >= out_size) break;

        slot_pc = read_bit(&reader);
        slot_m8 = read_bit(&reader);
        if (slot_pc == 0) {
            b9 = read_bit(&reader);
            if (slot_m8 == 0) {
                if (b9 != 0) EMIT(fill);
            } else {
                EMIT(fill);
                EMIT(fill);
                if (out_pos >= out_size) break;
                if (b9 != 0) EMIT(fill);
            }
            continue;
        }

        for (int index = 0; index < 4 && out_pos < out_size; index++) {
            EMIT(fill);
        }
        if (out_pos >= out_size) break;
        b9 = read_bit(&reader);
        if (slot_m8 == 0) {
            if (b9 != 0) EMIT(fill);
            continue;
        }
        EMIT(fill);
        EMIT(fill);
        if (out_pos >= out_size) break;
        if (b9 == 0) continue;
        EMIT(fill);
        if (out_pos >= out_size) break;

        for (;;) {
            unsigned int count = read_byte(&reader);
            unsigned int original_count;
            if (count > 0x7fU) {
                count = ((count - 0x80U) << 8) + read_byte(&reader);
            }
            original_count = count;
            while (count-- != 0 && out_pos < out_size) {
                EMIT(fill);
            }
            if (original_count != 0x7fffU) break;
            if (reader.pos >= reader.size) break;
        }
    }
#undef EMIT
}

static int
validate_transpose_args(
    Py_ssize_t record_size,
    Py_ssize_t record_count,
    Py_ssize_t *row_start,
    Py_ssize_t *row_count)
{
    if (record_size < 0 || record_count < 0) {
        PyErr_SetString(PyExc_ValueError, "transpose dimensions must be non-negative");
        return 0;
    }
    if (record_size != 0 && record_count > MAX_TRANSPOSE_OUTPUT / record_size) {
        PyErr_SetString(PyExc_ValueError, "transpose output is too large");
        return 0;
    }
    if (*row_start < 0) *row_start = 0;
    if (*row_start > record_count) *row_start = record_count;
    if (*row_count < 0) *row_count = 0;
    if (*row_count > record_count - *row_start) {
        *row_count = record_count - *row_start;
    }
    return 1;
}

static void
transpose_into(
    const unsigned char *src,
    Py_ssize_t src_size,
    unsigned char *out,
    Py_ssize_t record_size,
    Py_ssize_t record_count,
    Py_ssize_t row_start,
    Py_ssize_t row_count)
{
    Py_ssize_t column;
    memset(out, 0, (size_t)(record_size * row_count));
    for (column = 0; column < record_size; column++) {
        int plane;
        for (plane = 0; plane < 8; plane++) {
            Py_ssize_t row;
            Py_ssize_t plane_start = (column * 8 + plane) * record_count;
            unsigned char mask = (unsigned char)(1U << plane);
            for (row = row_start; row < row_start + row_count; row++) {
                Py_ssize_t bit_offset = plane_start + row;
                Py_ssize_t byte_offset = bit_offset >> 3;
                if (byte_offset < src_size &&
                    ((src[byte_offset] >> (bit_offset & 7)) & 1U)) {
                    out[(row - row_start) * record_size + column] |= mask;
                }
            }
        }
    }
}

static PyObject *
native_decode_bitrle(PyObject *self, PyObject *args)
{
    const unsigned char *src;
    Py_ssize_t src_size;
    Py_ssize_t expected_size;
    Py_ssize_t out_size;
    PyObject *result;
    unsigned char *out;
    (void)self;

    if (!PyArg_ParseTuple(args, "y#n:decode_bitrle", &src, &src_size, &expected_size)) {
        return NULL;
    }
    (void)expected_size;
    out_size = declared_bitrle_size(src, src_size);
    if (out_size == 0) return PyBytes_FromStringAndSize("", 0);
    result = PyBytes_FromStringAndSize(NULL, out_size);
    if (result == NULL) return NULL;
    out = (unsigned char *)PyBytes_AsString(result);
    if (out == NULL) {
        Py_DECREF(result);
        return NULL;
    }
    Py_BEGIN_ALLOW_THREADS
    decode_bitrle_into(src, src_size, out, out_size);
    Py_END_ALLOW_THREADS
    return result;
}

static PyObject *
native_transpose(PyObject *self, PyObject *args, PyObject *kwargs)
{
    static char *keywords[] = {
        "src", "record_size", "record_count", "row_start", "row_count", NULL
    };
    const unsigned char *src;
    Py_ssize_t src_size;
    Py_ssize_t record_size;
    Py_ssize_t record_count;
    Py_ssize_t row_start = 0;
    Py_ssize_t row_count;
    PyObject *row_count_object = Py_None;
    PyObject *result;
    unsigned char *out;
    (void)self;

    if (!PyArg_ParseTupleAndKeywords(
            args, kwargs, "y#nn|nO:transpose", keywords,
            &src, &src_size, &record_size, &record_count,
            &row_start, &row_count_object)) {
        return NULL;
    }
    if (row_count_object == Py_None) {
        row_count = record_count - row_start;
    } else {
        row_count = PyLong_AsSsize_t(row_count_object);
        if (row_count == -1 && PyErr_Occurred()) return NULL;
    }
    if (!validate_transpose_args(
            record_size, record_count, &row_start, &row_count)) {
        return NULL;
    }
    result = PyBytes_FromStringAndSize(NULL, record_size * row_count);
    if (result == NULL) return NULL;
    out = (unsigned char *)PyBytes_AsString(result);
    if (out == NULL) {
        Py_DECREF(result);
        return NULL;
    }
    Py_BEGIN_ALLOW_THREADS
    transpose_into(
        src, src_size, out,
        record_size, record_count, row_start, row_count);
    Py_END_ALLOW_THREADS
    return result;
}

static PyMethodDef native_methods[] = {
    {"decode_bitrle", native_decode_bitrle, METH_VARARGS,
     "Decode an hd3.1 BitRLE stream."},
    {"transpose", (PyCFunction)native_transpose, METH_VARARGS | METH_KEYWORDS,
     "Transpose selected bit-plane rows into row-major records."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef native_module = {
    PyModuleDef_HEAD_INIT,
    "_compression_native",
    "Native BitRLE and bit-plane codecs.",
    -1,
    native_methods
};

PyMODINIT_FUNC
PyInit__compression_native(void)
{
    return PyModule_Create(&native_module);
}
