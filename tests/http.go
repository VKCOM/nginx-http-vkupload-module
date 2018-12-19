package main

import (
    "encoding/json"
    "io/ioutil"
    "net/http"
    "strconv"
    "time"
)

func startHTTPTestServer(listen string) {
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        var data UploadResultData
        data.Path = r.FormValue("file_path")
        data.Md5 = r.FormValue("file_md5")

        size, _ := strconv.ParseInt(r.FormValue("file_size"), 10, 32)
        data.Size = int(size)

        w.Header().Set("Content-Type", "application/json")
        w.WriteHeader(http.StatusOK)

        json.NewEncoder(w).Encode(&data)
    })

    http.ListenAndServe(listen, nil)
}

func createHTTPClient(maMaxIdleConnections int, requestTimeout int) *http.Client {
    client := &http.Client{
        Transport: &http.Transport{
            MaxIdleConnsPerHost: maMaxIdleConnections,
        },

        Timeout: time.Duration(requestTimeout) * time.Second,
    }

    return client
}

func doHTTPTestServerRequest(client *http.Client, request *http.Request) (*UploadResult, error) {
    response, err := client.Do(request)
    if err != nil {
        var result UploadResult
        result.err = err

        return &result, err
    }

    defer response.Body.Close()

    var result UploadResult
    result.StatusCode = response.StatusCode

    if response.StatusCode == 200 {
        body, err := ioutil.ReadAll(response.Body)
        if err != nil {
            return nil, err
        }

        if err := json.Unmarshal(body, &result.Data); err != nil {
            return nil, err
        }
    } else if response.StatusCode == 201 {
        body, err := ioutil.ReadAll(response.Body)
        if err != nil {
            return nil, err
        }

        result.ContentRangesBody = string(body)

        for k, v := range response.Header {
            if k == "Range" {
                result.ContentRangesHeader = v[0]
            }
        }
    }

    return &result, nil
}
