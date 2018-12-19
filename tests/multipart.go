package main

import (
    "net/textproto"
    "strings"
)

const (
    MultipartTestFileContent = "multipart test file content"
)

func init() {
    Tests = append(Tests, TestMultipartSimple())
    Tests = append(Tests, TestMultipartSimple2())
    Tests = append(Tests, TestMultipartSmall())
    Tests = append(Tests, TestMultipartBig())
    Tests = append(Tests, TestMultipartWrongName1())
    Tests = append(Tests, TestMultipartWrongName2())
    Tests = append(Tests, TestMultipartEmptyName())
    Tests = append(Tests, TestMultipartEmptyFilename())
    Tests = append(Tests, TestMultipartEmptyContent())
    Tests = append(Tests, TestMultipartWithoutName())
    Tests = append(Tests, TestMultipartWithoutFilename())
    Tests = append(Tests, TestMultipartWithoutNameAndFilename())
    Tests = append(Tests, TestMultipartDoubleField1())
    Tests = append(Tests, TestMultipartDoubleField2())
}

func TestMultipartSimple() Test {
    return Test{
        Name: "multipart-simple",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadMultipartRequest{}
            request.Field("file", "video.mp4", MultipartTestFileContent)
            request.Validator(UploadResultValidateHTTPCode(200))
            request.Validator(UploadResultValidateFields(MultipartTestFileContent))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestMultipartSimple2() Test {
    return Test{
        Name: "multipart-simple-2",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadMultipartRequest{}
            request.Field("video", "video.mp4", MultipartTestFileContent)
            request.Validator(UploadResultValidateHTTPCode(200))
            request.Validator(UploadResultValidateFields(MultipartTestFileContent))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestMultipartSmall() Test {
    return Test{
        Name: "multipart-small",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadMultipartRequest{}
            request.Field("file", "video.mp4", "a")
            request.Validator(UploadResultValidateHTTPCode(200))
            request.Validator(UploadResultValidateFields("a"))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestMultipartBig() Test {
    return Test{
        Name: "multipart-big",

        GetUploadRequests: func() ([]UploadRequest, error) {
            str := strings.Repeat("a", 1024*1024*1-1024) // 1mb - 1kb (for headers)
            request := UploadMultipartRequest{}
            request.Field("file", "video.mp4", str)
            request.Validator(UploadResultValidateHTTPCode(200))
            request.Validator(UploadResultValidateFields(str))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestMultipartToBig() Test {
    return Test{
        Name: "multipart-to-big",

        GetUploadRequests: func() ([]UploadRequest, error) {
            str := strings.Repeat("a", 1024*1024*2) // 2mb
            request := UploadMultipartRequest{}
            request.Field("file", "video.mp4", str)
            request.Validator(UploadResultValidateHTTPCode(413))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestMultipartWrongName1() Test {
    return Test{
        Name: "multipart-wrong-name-1",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadMultipartRequest{}
            request.Field("file_test", "video.mp4", MultipartTestFileContent)
            request.Validator(UploadResultValidateHTTPCode(400))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestMultipartWrongName2() Test {
    return Test{
        Name: "multipart-wrong-name-2",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadMultipartRequest{}
            request.Field("test_file", "video.mp4", MultipartTestFileContent)
            request.Validator(UploadResultValidateHTTPCode(400))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestMultipartEmptyName() Test {
    return Test{
        Name: "multipart-empty-name",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadMultipartRequest{}
            request.Field("", "video.mp4", MultipartTestFileContent)
            request.Validator(UploadResultValidateHTTPCode(400))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestMultipartEmptyFilename() Test {
    return Test{
        Name: "multipart-empty-filename",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadMultipartRequest{}
            request.Field("file", "", MultipartTestFileContent)
            request.Validator(UploadResultValidateHTTPCode(200))
            request.Validator(UploadResultValidateFields(MultipartTestFileContent))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestMultipartEmptyContent() Test {
    return Test{
        Name: "multipart-empty-content",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadMultipartRequest{}
            request.Field("file", "video.mp4", "")
            request.Validator(UploadResultValidateHTTPCode(400))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestMultipartWithoutName() Test {
    return Test{
        Name: "multipart-empty-without-name",

        GetUploadRequests: func() ([]UploadRequest, error) {
            header := make(textproto.MIMEHeader)
            header.Set("Content-Disposition", `form-data; filename="video.mp4"`)
            header.Set("Content-Type", "application/octet-stream")

            request := UploadMultipartRequest{}
            request.FieldRaw(header, MultipartTestFileContent)
            request.Validator(UploadResultValidateHTTPCode(400))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestMultipartWithoutFilename() Test {
    return Test{
        Name: "multipart-empty-without-filename",

        GetUploadRequests: func() ([]UploadRequest, error) {
            header := make(textproto.MIMEHeader)
            header.Set("Content-Disposition", `form-data; name="file"`)
            header.Set("Content-Type", "application/octet-stream")

            request := UploadMultipartRequest{}
            request.FieldRaw(header, MultipartTestFileContent)
            request.Validator(UploadResultValidateHTTPCode(200))
            request.Validator(UploadResultValidateFields(MultipartTestFileContent))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestMultipartWithoutNameAndFilename() Test {
    return Test{
        Name: "multipart-empty-without-name-and-filename",

        GetUploadRequests: func() ([]UploadRequest, error) {
            header := make(textproto.MIMEHeader)
            header.Set("Content-Disposition", `form-data;`)
            header.Set("Content-Type", "application/octet-stream")

            request := UploadMultipartRequest{}
            request.FieldRaw(header, MultipartTestFileContent)
            request.Validator(UploadResultValidateHTTPCode(400))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestMultipartDoubleField1() Test {
    return Test{
        Name: "multipart-simple-double-field-1",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadMultipartRequest{}

            request.Field("file", "video.mp4", MultipartTestFileContent)
            request.Field("file", "video.mp4", "test string 2")
            request.Validator(UploadResultValidateHTTPCode(200))
            request.Validator(UploadResultValidateFields(MultipartTestFileContent))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestMultipartDoubleField2() Test {
    return Test{
        Name: "multipart-simple-double-field-2",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadMultipartRequest{}

            request.Field("file_test", "video.mp4", "test string 3")
            request.Field("file", "video.mp4", MultipartTestFileContent)
            request.Field("file", "video.mp4", "test string 2")
            request.Validator(UploadResultValidateHTTPCode(200))
            request.Validator(UploadResultValidateFields(MultipartTestFileContent))

            return []UploadRequest{&request}, nil
        },
    }
}
