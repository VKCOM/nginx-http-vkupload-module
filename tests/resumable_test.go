package vkupload_tests

import (
    "testing"
)

func partialChunkTest(t *testing.T, sessionId, bodyRange, body, exceptRange string) {
    uploadTest.Post("/upload").
        SetHeader("Content-Disposition", `attachment; name="fieldname"; filename="filename.jpg"`).
        SetHeader("Session-ID", sessionId).
        SetHeader("Content-Range", `bytes `+bodyRange).
        BodyString(body).
        Expect(t).
        Status(201).
        HeaderEquals("Range", exceptRange).
        BodyEquals(exceptRange).
        Done()
}

func finalChunkTest(t *testing.T, sessionId, bodyRange, body, exceptBody string) {
    uploadTest.Post("/upload").
        SetHeader("Content-Disposition", `attachment; name="fieldname"; filename="filename.jpg"`).
        SetHeader("Session-ID", sessionId).
        SetHeader("Content-Range", `bytes `+bodyRange).
        BodyString(body).
        Expect(t).
        Status(200).
        Type("json").
        AssertFunc(assertUploadResultFields(exceptBody)).
        Done()
}

func TestResumableSimple(t *testing.T) {
    partialChunkTest(t, "1", "0-1/4", "te", "0-1/4")
    finalChunkTest(t, "1", "2-3/4", "st", "test")
}

func TestResumableOverflow(t *testing.T) {
    partialChunkTest(t, "2", "0-2/4", "tes", "0-2/4")
    finalChunkTest(t, "2", "1-3/4", "est", "test")
}

func TestResumableOverflow2(t *testing.T) {
    partialChunkTest(t, "3", "1-2/4", "AA", "1-2/4")
    partialChunkTest(t, "3", "1-3/4", "AAA", "1-3/4")
    finalChunkTest(t, "3", "0-3/4", "test", "test")
}

func TestResumableOverflow3(t *testing.T) {
    partialChunkTest(t, "4", "0-2/4", "tes", "0-2/4")
    partialChunkTest(t, "4", "0-1/4", "AA", "0-2/4")
    finalChunkTest(t, "4", "0-3/4", "AAAt", "test")
}

func TestResumableTotalUnknown(t *testing.T) {
    partialChunkTest(t, "5", "2-3/*", "st", "2-3/*")
    finalChunkTest(t, "5", "0-1/4", "te", "test")
}

func TestResumableFull(t *testing.T) {
    finalChunkTest(t, "6", "0-3/4", "test", "test")
}

func TestResumableSimple2(t *testing.T) {
    partialChunkTest(t, "7", "4-5/*", "te", "4-5/*")
    partialChunkTest(t, "7", "0-1/*", "te", "0-1/*,4-5/*")
    partialChunkTest(t, "7", "8-9/*", "te", "0-1/*,4-5/*,8-9/*")
    partialChunkTest(t, "7", "1-3/12", "est", "0-5/12,8-9/12")

    uploadTest.Post("/upload").
        SetHeader("Content-Disposition", `attachment; name="fieldname"; filename="filename.jpg"`).
        SetHeader("Session-ID", "7").
        SetHeader("Content-Range", `bytes 11-12/*`).
        BodyString("AA").
        Expect(t).
        Status(400).
        Done()

    uploadTest.Post("/upload").
        SetHeader("Content-Disposition", `attachment; name="fieldname"; filename="filename.jpg"`).
        SetHeader("Session-ID", "7").
        SetHeader("Content-Range", `bytes 0-2/14`).
        BodyString("AA").
        Expect(t).
        Status(400).
        Done()

    uploadTest.Post("/upload").
        SetHeader("Content-Disposition", `attachment; name="fieldname"; filename="filename.jpg"`).
        SetHeader("Session-ID", "7").
        SetHeader("Content-Range", `bytes 0-2/*`).
        BodyString("AAAA").
        Expect(t).
        Status(400).
        Done()

    finalChunkTest(t, "7", "6-11/*", "sttest", "testtesttest")
}
