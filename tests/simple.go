package main

import "strings"

const (
    SimpleTestFileContent = "simple test file content"
)

func init() {
    Tests = append(Tests, TestSimpleSimple())
    Tests = append(Tests, TestSimpleAttachment())
    Tests = append(Tests, TestSimpleWithoutName())
    Tests = append(Tests, TestSimpleWithoutFilename())
    Tests = append(Tests, TestSimpleWithoutNameAndFilename())
    Tests = append(Tests, TestSimpleWithoutNameAndFilename2())
    Tests = append(Tests, TestSimpleBig())
    Tests = append(Tests, TestSimpleToBig())
}

func TestSimpleSimple() Test {
    return Test{
        Name: "simple-simple",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadSimpleRequest{}
            request.Content(SimpleTestFileContent)
            request.ContentDisposition(`form-data; name="fieldname"; filename="filename.jpg"`)
            request.Validator(UploadResultValidateHTTPCode(200))
            request.Validator(UploadResultValidateFields(SimpleTestFileContent))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestSimpleAttachment() Test {
    return Test{
        Name: "simple-attachment",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadSimpleRequest{}
            request.Content(SimpleTestFileContent)
            request.ContentDisposition(`attachment; name="fieldname"; filename="filename.jpg"`)
            request.Validator(UploadResultValidateHTTPCode(200))
            request.Validator(UploadResultValidateFields(SimpleTestFileContent))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestSimpleWithoutName() Test {
    return Test{
        Name: "simple-without-name",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadSimpleRequest{}
            request.Content(SimpleTestFileContent)
            request.ContentDisposition(`form-data; filename="filename.jpg"`)
            request.Validator(UploadResultValidateHTTPCode(200))
            request.Validator(UploadResultValidateFields(SimpleTestFileContent))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestSimpleWithoutFilename() Test {
    return Test{
        Name: "simple-without-filename",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadSimpleRequest{}
            request.Content(SimpleTestFileContent)
            request.ContentDisposition(`attachment; name="fieldname";`)
            request.Validator(UploadResultValidateHTTPCode(200))
            request.Validator(UploadResultValidateFields(SimpleTestFileContent))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestSimpleWithoutNameAndFilename() Test {
    return Test{
        Name: "simple-without-name-and-filename",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadSimpleRequest{}
            request.Content(SimpleTestFileContent)
            request.ContentDisposition(`form-data;`)
            request.Validator(UploadResultValidateHTTPCode(200))
            request.Validator(UploadResultValidateFields(SimpleTestFileContent))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestSimpleWithoutNameAndFilename2() Test {
    return Test{
        Name: "simple-without-name-and-filename-2",

        GetUploadRequests: func() ([]UploadRequest, error) {
            request := UploadSimpleRequest{}
            request.Content(SimpleTestFileContent)
            request.ContentDisposition(`form-data`)
            request.Validator(UploadResultValidateHTTPCode(200))
            request.Validator(UploadResultValidateFields(SimpleTestFileContent))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestSimpleBig() Test {
    return Test{
        Name: "simple-big",

        GetUploadRequests: func() ([]UploadRequest, error) {
            str := strings.Repeat("a", 1024*1024*1-1024)

            request := UploadSimpleRequest{}
            request.Content(str)
            request.ContentDisposition(`form-data; name="fieldname"; filename="filename.jpg"`)
            request.Validator(UploadResultValidateHTTPCode(200))
            request.Validator(UploadResultValidateFields(str))

            return []UploadRequest{&request}, nil
        },
    }
}

func TestSimpleToBig() Test {
    return Test{
        Name: "simple-to-big",

        GetUploadRequests: func() ([]UploadRequest, error) {
            str := strings.Repeat("a", 1024*1024*2)

            request := UploadSimpleRequest{}
            request.Content(str)
            request.ContentDisposition(`form-data; name="fieldname"; filename="filename.jpg"`)
            request.Validator(UploadResultValidateHTTPCode(413))

            return []UploadRequest{&request}, nil
        },
    }
}
