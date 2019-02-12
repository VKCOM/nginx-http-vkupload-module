package vkupload_tests

import (
    "strings"
    "testing"
)

func TestSimpleSimple(t *testing.T) {
    uploadTest.Post("/upload").
        SetHeader("Content-Disposition", `form-data; name="fieldname"; filename="filename.jpg"`).
        BodyString(simpleFileContent).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields(simpleFileContent)).
        Done()
}

func TestSimpleAttachment(t *testing.T) {
    uploadTest.Post("/upload").
        SetHeader("Content-Disposition", `attachment; name="fieldname"; filename="filename.jpg"`).
        BodyString(simpleFileContent).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields(simpleFileContent)).
        Done()
}

func TestSimpleWithoutName(t *testing.T) {
    uploadTest.Post("/upload").
        SetHeader("Content-Disposition", `form-data; filename="filename.jpg"`).
        BodyString(simpleFileContent).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields(simpleFileContent)).
        Done()
}

func TestSimpleWithoutFilename(t *testing.T) {
    uploadTest.Post("/upload").
        SetHeader("Content-Disposition", `attachment; name="fieldname";`).
        BodyString(simpleFileContent).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields(simpleFileContent)).
        Done()
}

func TestSimpleWithoutNameAndFilename(t *testing.T) {
    uploadTest.Post("/upload").
        SetHeader("Content-Disposition", `form-data;`).
        BodyString(simpleFileContent).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields(simpleFileContent)).
        Done()
}

func TestSimpleWithoutNameAndFilename2(t *testing.T) {
    uploadTest.Post("/upload").
        SetHeader("Content-Disposition", `form-data`).
        BodyString(simpleFileContent).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields(simpleFileContent)).
        Done()
}

func TestSimpleBig(t *testing.T) {
    str := strings.Repeat("a", 1024*1024*1-1024)

    uploadTest.Post("/upload").
        SetHeader("Content-Disposition", `form-data; name="fieldname"; filename="filename.jpg"`).
        BodyString(str).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields(str)).
        Done()
}

func TestSimpleToBig(t *testing.T) {
    str := strings.Repeat("a", 1024*1024*2)

    uploadTest.Post("/upload").
        SetHeader("Content-Disposition", `form-data; name="fieldname"; filename="filename.jpg"`).
        BodyString(str).
        Expect(t).
        Status(413).
        Done()
}
