package vkupload_tests

import (
    "bytes"
    "crypto/md5"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "io/ioutil"
    "mime/multipart"
    "net/http"
    "net/textproto"
    "os"
    "strconv"

    baloo "gopkg.in/h2non/baloo.v3"
)

var (
    uploadTest        *baloo.Client
    simpleFileContent = "simple test file content"
)

type uploadResultData struct {
    Path string
    Md5  string
    Size int
}

type multipartField struct {
    headers map[string]string
    value   string
}

func init() {
    var backend = os.Getenv("VKUPLOAD_BACKEND_LISTEN")
    if len(backend) == 0 {
        backend = "127.0.0.1:8080"
    }

    startHTTPTestServer(backend)

    var nginx = os.Getenv("VKUPLOAD_UPLOAD_URL")
    if len(nginx) == 0 {
        nginx = "http://127.0.0.1:8081"
    }

    uploadTest = baloo.New(nginx)
}

func startHTTPTestServer(listen string) {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        var data uploadResultData

        data.Path = r.FormValue("file_path")
        data.Md5 = r.FormValue("file_md5")

        size, _ := strconv.ParseInt(r.FormValue("file_size"), 10, 32)
        data.Size = int(size)

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)

        json.NewEncoder(w).Encode(&data)
    })

    go http.ListenAndServe(listen, nil)
}

func multipartBodyString(fields []multipartField) (string, string) {
    var body bytes.Buffer
    w := multipart.NewWriter(&body)

    for _, field := range fields {
        headers := make(textproto.MIMEHeader)

        for name, header := range field.headers {
            headers.Set(name, header)
        }

        fw, _ := w.CreatePart(headers)
        fw.Write([]byte(field.value))
    }

    w.Close()
    return body.String(), w.FormDataContentType()
}

func multipartBodySimple(contentDisposition, value string) (string, string) {
    fields := []multipartField{
        {
            headers: map[string]string{
                "Content-Disposition": contentDisposition,
            },
            value: value,
        },
    }

    return multipartBodyString(fields)
}

/** --- asserts --- */

func assertUploadResultFields(origianl string) func(*http.Response, *http.Request) error {
    return func(response *http.Response, request *http.Request) error {
        var data uploadResultData

        body, err := ioutil.ReadAll(response.Body)
        if err != nil {
            return err
        }

        if err := json.Unmarshal(body, &data); err != nil {
            return err
        }

        if len(data.Path) == 0 {
            return errors.New(fmt.Sprintf("field with path is empty"))
        }

        if len(data.Md5) == 0 {
            return errors.New(fmt.Sprintf("field with md5 is empty"))
        }

        if _, err := os.Stat(data.Path); os.IsNotExist(err) {
            return errors.New(fmt.Sprintf("path <%s> with upload not exists", data.Path))
        }

        f, err := os.Open(data.Path)
        if err != nil {
            return errors.New(fmt.Sprintf("error open <%s> upload file", data.Path))
        }

        defer f.Close()

        md5Ctx := md5.New()
        if _, err := io.Copy(md5Ctx, f); err != nil {
            return errors.New(fmt.Sprintf("error read <%s> upload file", data.Path))
        }

        md5Str := hex.EncodeToString(md5Ctx.Sum(nil))
        if md5Str != data.Md5 {
            return errors.New(fmt.Sprintf("file <%s> md5 not equal, %s (expected) != %s (actual)",
                data.Path, md5Str, data.Md5))
        }

        md5OriginlCtx := md5.New()
        io.WriteString(md5OriginlCtx, origianl)
        md5OriginalStr := hex.EncodeToString(md5OriginlCtx.Sum(nil))
        if md5OriginalStr != data.Md5 {
            return errors.New(fmt.Sprintf("file <%s> md5 not equal with original, %s (expected) != %s (actual)",
                data.Path, md5OriginalStr, data.Md5))
        }

        return nil
    }
}
