package vkupload_tests

import (
    "strings"
    "testing"
)

func TestMultipartSimple(t *testing.T) {
    body, contentType := multipartBodySimple(`attachment; name="file"; filename="filename.jpg"`, simpleFileContent)

    uploadTest.Post("/upload").
        SetHeader("Content-Type", contentType).
        BodyString(body).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields(simpleFileContent)).
        Done()
}

func TestMultipartSimple2(t *testing.T) {
    body, contentType := multipartBodySimple(`form-data; name="video"; filename="video.mp4"`, simpleFileContent)

    uploadTest.Post("/upload").
        SetHeader("Content-Type", contentType).
        BodyString(body).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields(simpleFileContent)).
        Done()
}

func TestMultipartSmall(t *testing.T) {
    body, contentType := multipartBodySimple(`form-data; name="video"; filename="video.mp4"`, "a")

    uploadTest.Post("/upload").
        SetHeader("Content-Type", contentType).
        BodyString(body).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields("a")).
        Done()
}

func TestMultipartBig(t *testing.T) {
    str := strings.Repeat("a", 1024*1024*1-1024) // 1mb - 1kb (for headers)
    body, contentType := multipartBodySimple(`form-data; name="video"; filename="video.mp4"`, str)

    uploadTest.Post("/upload").
        SetHeader("Content-Type", contentType).
        BodyString(body).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields(str)).
        Done()
}

func TestMultipartWrongName1(t *testing.T) {
    body, contentType := multipartBodySimple(`attachment; name="file_test"; filename="filename.jpg"`, simpleFileContent)

    uploadTest.Post("/upload").
        SetHeader("Content-Type", contentType).
        BodyString(body).
        Expect(t).
        Status(400).
        Done()
}

func TestMultipartWrongName2(t *testing.T) {
    body, contentType := multipartBodySimple(`attachment; name="test_file"; filename="filename.jpg"`, simpleFileContent)

    uploadTest.Post("/upload").
        SetHeader("Content-Type", contentType).
        BodyString(body).
        Expect(t).
        Status(400).
        Done()
}

func TestMultipartEmptyName(t *testing.T) {
    body, contentType := multipartBodySimple(`attachment; name=""; filename="filename.jpg"`, simpleFileContent)

    uploadTest.Post("/upload").
        SetHeader("Content-Type", contentType).
        BodyString(body).
        Expect(t).
        Status(400).
        Done()
}

func TestMultipartEmptyFilename(t *testing.T) {
    body, contentType := multipartBodySimple(`attachment; name="video"; filename=""`, simpleFileContent)

    uploadTest.Post("/upload").
        SetHeader("Content-Type", contentType).
        BodyString(body).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields(simpleFileContent)).
        Done()
}

func TestMultipartEmptyContent(t *testing.T) {
    body, contentType := multipartBodySimple(`attachment; name="video"; filename="filename.jpg"`, "")

    uploadTest.Post("/upload").
        SetHeader("Content-Type", contentType).
        BodyString(body).
        Expect(t).
        Status(400).
        Done()
}

func TestMultipartWithoutName(t *testing.T) {
    body, contentType := multipartBodySimple(`attachment; filename="filename.jpg"`, simpleFileContent)

    uploadTest.Post("/upload").
        SetHeader("Content-Type", contentType).
        BodyString(body).
        Expect(t).
        Status(400).
        Done()
}

func TestMultipartWithoutFilename(t *testing.T) {
    body, contentType := multipartBodySimple(`attachment; name="video"`, simpleFileContent)

    uploadTest.Post("/upload").
        SetHeader("Content-Type", contentType).
        BodyString(body).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields(simpleFileContent)).
        Done()
}

func TestMultipartWrongFilename(t *testing.T) {
    body, contentType := multipartBodySimple(`attachment; name="video"; filename=`, simpleFileContent)

    uploadTest.Post("/upload").
        SetHeader("Content-Type", contentType).
        BodyString(body).
        Expect(t).
        Status(400).
        Done()
}

func TestMultipartDoubleField1(t *testing.T) {
    fields := []multipartField{
        {
            headers: map[string]string{
                "Content-Disposition": `attachment; name="video"; filename="filename.jpg"`,
            },
            value: simpleFileContent,
        },
        {
            headers: map[string]string{
                "Content-Disposition": `attachment; name="video"; filename="filename.jpg"`,
            },
            value: "test string 2",
        },
    }

    body, contentType := multipartBodyString(fields)

    uploadTest.Post("/upload").
        SetHeader("Content-Type", contentType).
        BodyString(body).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields(simpleFileContent)).
        Done()
}

func TestMultipartDoubleField2(t *testing.T) {
    fields := []multipartField{
        {
            headers: map[string]string{
                "Content-Disposition": `attachment; name="file_test"; filename="filename.jpg"`,
            },
            value: simpleFileContent,
        },
        {
            headers: map[string]string{
                "Content-Disposition": `attachment; name="file"; filename="filename.jpg"`,
            },
            value: simpleFileContent,
        },
        {
            headers: map[string]string{
                "Content-Disposition": `attachment; name="file"; filename="filename.jpg"`,
            },
            value: "test string 2",
        },
    }

    body, contentType := multipartBodyString(fields)

    uploadTest.Post("/upload").
        SetHeader("Content-Type", contentType).
        BodyString(body).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields(simpleFileContent)).
        Done()
}
