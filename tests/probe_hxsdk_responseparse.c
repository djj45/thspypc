/*
 * Black-box probe for the 32-bit hxsdk.dll ResponseParse export.
 *
 * Build with the x86 MSVC toolchain, then pass one captured 8901 response.
 * The probe does not write files; it prints return values and output heads.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int (__cdecl *response_parse_fn)(
    const void *input,
    int input_size,
    void **output1,
    int *output1_size,
    void **output2,
    int *output2_size
);
typedef int (__cdecl *release_data_fn)(void *data);

static void print_head(const char *label, const unsigned char *data, int size)
{
    int index;
    int limit = size < 128 ? size : 128;

    printf("%s_size=%d\n", label, size);
    printf("%s_hex=", label);
    for (index = 0; index < limit; ++index) {
        printf("%02x%s", data[index], index + 1 == limit ? "" : " ");
    }
    printf("\n");
}

int main(int argc, char **argv)
{
    const wchar_t *dll_directory = L"D:\\同花顺软件\\同花顺";
    const wchar_t *dll_path;
    FILE *stream;
    long file_size;
    unsigned char *input;
    HMODULE module;
    response_parse_fn response_parse;
    release_data_fn release_data;
    void *output1 = NULL;
    void *output2 = NULL;
    int output1_size = 0;
    int output2_size = 0;
    int result;

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "usage: %s CAPTURE.bin [hxsdk|hdp]\n", argv[0]);
        return 2;
    }
    dll_path = argc == 3 && strcmp(argv[2], "hdp") == 0
        ? L"D:\\同花顺软件\\同花顺\\hdp.dll"
        : L"D:\\同花顺软件\\同花顺\\hxsdk.dll";
    stream = fopen(argv[1], "rb");
    if (stream == NULL) {
        perror("fopen");
        return 2;
    }
    if (fseek(stream, 0, SEEK_END) != 0) {
        perror("fseek");
        fclose(stream);
        return 2;
    }
    file_size = ftell(stream);
    if (file_size < 0 || fseek(stream, 0, SEEK_SET) != 0) {
        perror("ftell/fseek");
        fclose(stream);
        return 2;
    }
    input = (unsigned char *)calloc((size_t)file_size + 1, 1);
    if (input == NULL) {
        fclose(stream);
        return 2;
    }
    if (fread(input, 1, (size_t)file_size, stream) != (size_t)file_size) {
        perror("fread");
        free(input);
        fclose(stream);
        return 2;
    }
    fclose(stream);

    if (!SetDllDirectoryW(dll_directory)) {
        fprintf(stderr, "SetDllDirectoryW failed: %lu\n", GetLastError());
        free(input);
        return 3;
    }
    module = LoadLibraryW(dll_path);
    if (module == NULL) {
        fprintf(stderr, "LoadLibraryW failed: %lu\n", GetLastError());
        free(input);
        return 3;
    }
    response_parse = (response_parse_fn)GetProcAddress(module, "ResponseParse");
    release_data = (release_data_fn)GetProcAddress(module, "ReleaseData");
    if (response_parse == NULL || release_data == NULL) {
        fprintf(stderr, "GetProcAddress failed: %lu\n", GetLastError());
        FreeLibrary(module);
        free(input);
        return 3;
    }

    result = response_parse(
        input,
        (int)file_size,
        &output1,
        &output1_size,
        &output2,
        &output2_size
    );
    printf("result=%d input_size=%ld output1=%p output2=%p\n",
           result, file_size, output1, output2);
    if (output1 != NULL && output1_size >= 0) {
        print_head("output1", (const unsigned char *)output1, output1_size);
    }
    if (output2 != NULL && output2_size >= 0) {
        print_head("output2", (const unsigned char *)output2, output2_size);
    }

    if (output1 != NULL) {
        release_data(output1);
    }
    if (output2 != NULL) {
        release_data(output2);
    }
    FreeLibrary(module);
    free(input);
    return 0;
}
