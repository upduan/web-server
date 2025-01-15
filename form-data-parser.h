#pragma once

#include <string>

namespace util::fromdata {
    // boundary length [27 - 70]
    // Content-Type: multipart/form-data; boundary=<boundary>\r\n
    // \r\n
    // --boundary\r\n
    // Content-Disposition: form-data; name="name"\r\n
    // \r\n
    // value\r\n
    // --boundary\r\n
    // Content-Disposition: form-data; name="name"; filename="file-name"\r\n
    // Content-Type: application/octet-stream\r\n
    // \r\n
    // value\r\n
    // --boundary--\r\n
    constexpr std::size_t const INITIAL_FIELD_CAPACITY = 16;
    constexpr std::size_t const INITIAL_FILE_CAPACITY = 2;
    constexpr std::size_t const MAX_FILE_SIZE = 10 * 1024 * 1024;
    constexpr std::size_t const MAX_FIELD_NAME_SIZE = 64;
    constexpr std::size_t const MAX_FILENAME_SIZE = 128;
    constexpr std::size_t const MAX_MIMETYPE_SIZE = 128;
    constexpr std::size_t const MAX_VALUE_SIZE = 2048;

    enum class State {
        STATE_BOUNDARY,
        STATE_HEADER,
        STATE_KEY,
        STATE_VALUE,
        STATE_FILENAME,
        STATE_FILE_MIME_HEADER,
        STATE_MIMETYPE,
        STATE_FILE_BODY,
    };

    struct FileHeader {
        size_t offset; // Offset from the body of request as passed to parse_multipart.
        size_t size; // Computed file size.

        char filename[MAX_FILENAME_SIZE]; // Value of filename in Content-Disposition
        char mimetype[MAX_MIMETYPE_SIZE]; // Content-Type of the file.
        char field_name[MAX_FIELD_NAME_SIZE]; // Name of the field the file is associated with.
    };

    struct FormField {
        char name[MAX_FIELD_NAME_SIZE]; // Field name
        char value[MAX_VALUE_SIZE]; // Value associated with the field.
    };

    struct MultipartForm {
        FileHeader** files; // The array of file headers
        size_t num_files; // The number of files processed.

        FormField* fields; // Array of form field structs.
        size_t num_fields; // The number of fields.
    };

    enum MultipartCode {
        MULTIPART_OK,
        MEMORY_ALLOC_ERROR,
        INVALID_FORM_BOUNDARY,
        MAX_FILE_SIZE_EXCEEDED,
        FIELD_NAME_TOO_LONG,
        FILENAME_TOO_LONG,
        MIMETYPE_TOO_LONG,
        VALUE_TOO_LONG,
        EMPTY_FILE_CONTENT,
    };
} // namespace util::fromdata
