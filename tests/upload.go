package main

import (
    "bytes"
    "crypto/md5"
    "encoding/hex"
    "errors"
    "fmt"
    "io"
    "log"
    "mime/multipart"
    "net/http"
    "net/textproto"
    "os"
    "strings"
)

type UploadRequest interface {
    GetHTTPRequest(url string) (*http.Request, error)
    Validate(*UploadResult) error
}

type UploadResultData struct {
    Path string
    Md5  string
    Size int
}

type UploadResult struct {
    StatusCode int
    Data       UploadResultData
    err        error

    ContentRangesBody   string
    ContentRangesHeader string
}

type UploadValidatorFn func(result *UploadResult) error

type UploadValidator struct {
    fn UploadValidatorFn
}

/* --- mulipart --- */

type UploadMultipartField struct {
    header  textproto.MIMEHeader
    content []byte
}

type UploadMultipartRequest struct {
    fields    []UploadMultipartField
    validator []*UploadValidator
}

func (ur *UploadMultipartRequest) Field(name string, filename string, content string) *UploadMultipartRequest {
    header := make(textproto.MIMEHeader)
    header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, name, filename))
    header.Set("Content-Type", "application/octet-stream")

    ur.fields = append(ur.fields, UploadMultipartField{header: header, content: []byte(content)})
    return ur
}

func (ur *UploadMultipartRequest) FieldRaw(header textproto.MIMEHeader, content string) *UploadMultipartRequest {
    ur.fields = append(ur.fields, UploadMultipartField{header: header, content: []byte(content)})
    return ur
}

func (ur *UploadMultipartRequest) Validator(fn UploadValidatorFn) *UploadMultipartRequest {
    ur.validator = append(ur.validator, &UploadValidator{
        fn: fn,
    })

    return ur
}

func (ur *UploadMultipartRequest) Validate(result *UploadResult) error {
    for _, validator := range ur.validator {
        if err := validator.fn(result); err != nil {
            return err
        }
    }

    return nil
}

func (ur *UploadMultipartRequest) GetHTTPRequest(url string) (*http.Request, error) {
    var body bytes.Buffer
    w := multipart.NewWriter(&body)

    for _, field := range ur.fields {
        fw, err := w.CreatePart(field.header)
        if err != nil {
            return nil, err
        }

        _, err = fw.Write(field.content)
        if err != nil {
            return nil, err
        }
    }

    w.Close()

    req, err := http.NewRequest("POST", url, &body)
    if err != nil {
        return nil, err
    }

    req.Header.Set("Content-Type", w.FormDataContentType())
    return req, nil
}

/* --- mulipart --- */

type UploadSimpleRequest struct {
    content            string
    contentDisposition string
    validator          []*UploadValidator
}

func (us *UploadSimpleRequest) ContentDisposition(contentDisposition string) *UploadSimpleRequest {
    us.contentDisposition = contentDisposition
    return us
}

func (us *UploadSimpleRequest) Content(content string) *UploadSimpleRequest {
    us.content = content
    return us
}

func (us *UploadSimpleRequest) Validator(fn UploadValidatorFn) *UploadSimpleRequest {
    us.validator = append(us.validator, &UploadValidator{
        fn: fn,
    })

    return us
}

func (us *UploadSimpleRequest) Validate(result *UploadResult) error {
    for _, validator := range us.validator {
        if err := validator.fn(result); err != nil {
            return err
        }
    }

    return nil
}

func (us *UploadSimpleRequest) GetHTTPRequest(url string) (*http.Request, error) {
    req, err := http.NewRequest("POST", url, strings.NewReader(us.content))
    if err != nil {
        return nil, err
    }

    if len(us.contentDisposition) > 0 {
        req.Header.Set("Content-Disposition", us.contentDisposition)
    }

    return req, nil
}

/* --- standart validators --- */

func UploadResultValidateHTTPCode(code int) UploadValidatorFn {
    return func(result *UploadResult) error {
        if result.StatusCode != code {
            return errors.New(fmt.Sprintf("Error HTTP status code %d (expected) != %d (actual)", code, result.StatusCode))
        }

        log.Printf("\tsuccess check status code %d\n", code)
        return nil
    }
}

func UploadResultValidateFields(origianl string) UploadValidatorFn {
    return func(result *UploadResult) error {
        if len(result.Data.Path) == 0 {
            return errors.New(fmt.Sprintf("field with path is empty"))
        }

        if len(result.Data.Md5) == 0 {
            return errors.New(fmt.Sprintf("field with md5 is empty"))
        }

        if _, err := os.Stat(result.Data.Path); os.IsNotExist(err) {
            return errors.New(fmt.Sprintf("path <%s> with upload not exists", result.Data.Path))
        }

        f, err := os.Open(result.Data.Path)
        if err != nil {
            return errors.New(fmt.Sprintf("error open <%s> upload file", result.Data.Path))
        }

        defer f.Close()

        md5Ctx := md5.New()
        if _, err := io.Copy(md5Ctx, f); err != nil {
            return errors.New(fmt.Sprintf("error read <%s> upload file", result.Data.Path))
        }

        md5Str := hex.EncodeToString(md5Ctx.Sum(nil))
        if md5Str != result.Data.Md5 {
            return errors.New(fmt.Sprintf("file <%s> md5 not equal, %s (expected) != %s (actual)",
                result.Data.Path, md5Str, result.Data.Md5))
        }

        md5OriginlCtx := md5.New()
        io.WriteString(md5OriginlCtx, origianl)
        md5OriginalStr := hex.EncodeToString(md5OriginlCtx.Sum(nil))
        if md5OriginalStr != result.Data.Md5 {
            return errors.New(fmt.Sprintf("file <%s> md5 not equal with original, %s (expected) != %s (actual)",
                result.Data.Path, md5OriginalStr, result.Data.Md5))
        }

        log.Printf("\tsuccess check file <%s> with md5 %s\n", result.Data.Path, md5Str)

        return nil
    }
}

func UploadResultValidateRange(contentRange string) UploadValidatorFn {
    return func(result *UploadResult) error {
        if contentRange != result.ContentRangesHeader {
            return errors.New(fmt.Sprintf("Content-Range: <%s> not equal <%s>", result.ContentRangesHeader, contentRange))
        }

        if contentRange != result.ContentRangesBody {
            return errors.New(fmt.Sprintf("Content-Range in body <%s> not equal <%s>", result.ContentRangesHeader, contentRange))
        }

        log.Printf("\tsuccess check header Content-Range: <%s>\n", contentRange)
        return nil
    }
}
