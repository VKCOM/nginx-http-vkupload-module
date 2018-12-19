package main

import (
    "errors"
    "flag"
    "log"
    "os"
    "sync"
)

type TestFn func() ([]UploadRequest, error)

type Test struct {
    Name              string
    GetUploadRequests TestFn
    AllowHttpError    bool
}

var (
    Tests []Test
)

type Options struct {
    UploadUrl string
    Listen    string
    Test      string
    Count     int
    Parallel  int
}

func parseOptions() (*Options, error) {
    var options Options

    flag.StringVar(&options.Test, "test", "", "Test")
    flag.StringVar(&options.UploadUrl, "url", "", "Upload url")
    flag.StringVar(&options.Listen, "listen", "", "Listen address for upload backend")
    flag.IntVar(&options.Count, "count", 1, "Count iterations start tests")
    flag.IntVar(&options.Parallel, "parallel", 1, "Count parallel tests run")
    flag.Parse()

    if len(options.UploadUrl) == 0 {
        return nil, errors.New("--url required param")
    }

    if len(options.Listen) == 0 {
        return nil, errors.New("--listen required param")
    }

    if options.Count <= 0 {
        options.Count = 1
    }

    if options.Parallel <= 0 {
        options.Parallel = 1
    }

    return &options, nil
}

func main() {
    options, err := parseOptions()
    if err != nil {
        log.Printf("%s\n", err)
        os.Exit(1)
    }

    go startHTTPTestServer(options.Listen)

    var currentTests []Test

    if len(options.Test) > 0 {
        for _, test := range Tests {
            if test.Name == options.Test {
                currentTests = append(currentTests, test)
                break
            }
        }

        if len(currentTests) == 0 {
            log.Printf("Error: test <%s> not found\n", options.Test)
            os.Exit(1)
        }
    } else {
        currentTests = Tests
    }

    client := createHTTPClient(1, 30)
    limitter := make(chan *Test, options.Parallel)

    var wg sync.WaitGroup

    for i := 0; i < options.Count; i++ {
        for _, test := range currentTests {
            wg.Add(1)

            go func(test Test) {
                limitter <- &test

                requests, err := test.GetUploadRequests()
                if err != nil {
                    log.Fatal(err)
                }

                log.Printf("<%s> - start test\n", test.Name)

                for n, uploadRequest := range requests {
                    log.Printf("<%s | request-%d> - start\n", test.Name, n)

                    httpRequest, err := uploadRequest.GetHTTPRequest(options.UploadUrl)
                    if err != nil {
                        log.Printf("<%s | request-%d> - error create http request: %s\n", test.Name, n, err)
                        os.Exit(1)
                    }

                    result, err := doHTTPTestServerRequest(client, httpRequest)
                    if err != nil {
                        if !test.AllowHttpError {
                            log.Printf("<%s | request-%d> - error http request: %s\n", test.Name, n, err)
                            continue
                        }
                    }

                    if err := uploadRequest.Validate(result); err != nil {
                        log.Printf("<%s | request-%d> - error: %s\n", test.Name, n, err)
                        continue
                    }

                    log.Printf("<%s | request-%d> - succcess\n", test.Name, n)
                }

                <-limitter
                wg.Done()
            }(test)
        }
    }

    wg.Wait()
}
