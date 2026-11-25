// Known-answer checks against the live555 libraries (built with the project's normal flags):
// each check prints "PASS <name>" or "FAIL <name>"; mayhem/test.sh counts them.
#include <liveMedia.hh>
#include <BasicUsageEnvironment.hh>
#include <RTSPCommon.hh>
#include <Base64.hh>
#include <stdio.h>
#include <string.h>
#include <math.h>

static int failures = 0;
static void report(bool ok, char const* name) {
  printf("%s %s\n", ok ? "PASS" : "FAIL", name);
  if (!ok) ++failures;
}

int main() {
  TaskScheduler* scheduler = BasicTaskScheduler::createNew();
  UsageEnvironment* env = BasicUsageEnvironment::createNew(*scheduler);

  {  // RTSP request line + headers
    char const* req = "SETUP rtsp://example.com/media/track1 RTSP/1.0\r\nCSeq: 42\r\n"
                      "Session: ABCDEF01\r\nContent-Length: 0\r\n\r\n";
    char cmd[64], pre[256], suf[256], cseq[64], sess[64];
    unsigned contentLength = 99; Boolean rtsps = True;
    Boolean ok = parseRTSPRequestString(req, strlen(req), cmd, sizeof cmd, pre, sizeof pre, suf, sizeof suf,
                                        cseq, sizeof cseq, sess, sizeof sess, contentLength, rtsps);
    report(ok && strcmp(cmd, "SETUP") == 0, "rtsp_request_command");
    report(ok && strcmp(pre, "media") == 0 && strcmp(suf, "track1") == 0, "rtsp_request_url");
    report(ok && strcmp(cseq, "42") == 0 && strcmp(sess, "ABCDEF01") == 0 && contentLength == 0 && !rtsps, "rtsp_request_headers");
    report(!parseRTSPRequestString("garbage", 7, cmd, sizeof cmd, pre, sizeof pre, suf, sizeof suf,
                                   cseq, sizeof cseq, sess, sizeof sess, contentLength, rtsps), "rtsp_request_rejects_garbage");
  }
  {  // Range header
    double start = -1, end = -1; char* absStart = NULL; char* absEnd = NULL; Boolean now = True;
    Boolean ok = parseRangeHeader("Range: npt=1.5-3.25\r\n", start, end, absStart, absEnd, now);
    report(ok && fabs(start - 1.5) < 1e-9 && fabs(end - 3.25) < 1e-9 && !now, "range_header_npt");
    delete[] absStart; delete[] absEnd;
    float scale = 0;
    report(parseScaleHeader("Scale: 2.5\r\n", scale) && fabs(scale - 2.5f) < 1e-6, "scale_header");
  }
  {  // Base64
    unsigned n = 0;
    unsigned char* out = base64Decode("aGVsbG8gd29ybGQ=", n);
    report(n == 11 && memcmp(out, "hello world", 11) == 0, "base64_decode");
    delete[] out;
    char* enc = base64Encode("live555", 7);
    report(strcmp(enc, "bGl2ZTU1NQ==") == 0, "base64_encode");
    delete[] enc;
  }
  {  // SDP
    char const* sdp =
      "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Test Session\r\nt=0 0\r\na=range:npt=0-12.5\r\n"
      "m=video 0 RTP/AVP 96\r\nc=IN IP4 0.0.0.0\r\na=rtpmap:96 H264/90000\r\n"
      "a=fmtp:96 packetization-mode=1;profile-level-id=42e01f;sprop-parameter-sets=Z0LgH9oBQBbpUgAAAwACAAADAGQeMGVA,aM48gA==\r\n"
      "a=control:track1\r\n"
      "m=audio 0 RTP/AVP 97\r\nc=IN IP4 0.0.0.0\r\na=rtpmap:97 MPEG4-GENERIC/44100/2\r\n"
      "a=fmtp:97 streamtype=5;mode=AAC-hbr;config=1210;sizelength=13\r\na=control:track2\r\n";
    MediaSession* s = MediaSession::createNew(*env, sdp);
    report(s != NULL && strcmp(s->sessionName(), "Test Session") == 0, "sdp_session_name");
    report(s != NULL && fabs(s->playEndTime() - 12.5) < 1e-9, "sdp_range");
    unsigned count = 0; bool video = false, audio = false;
    if (s != NULL) {
      MediaSubsessionIterator it(*s);
      MediaSubsession* sub;
      while ((sub = it.next()) != NULL) {
        ++count;
        if (strcmp(sub->mediumName(), "video") == 0)
          video = strcmp(sub->codecName(), "H264") == 0 && sub->rtpTimestampFrequency() == 90000
                  && strcmp(sub->controlPath(), "track1") == 0 && sub->attrVal_unsigned("packetization-mode") == 1;
        if (strcmp(sub->mediumName(), "audio") == 0)
          audio = strcmp(sub->codecName(), "MPEG4-GENERIC") == 0 && sub->rtpTimestampFrequency() == 44100
                  && sub->numChannels() == 2 && strcmp(sub->fmtp_config(), "1210") == 0;
      }
    }
    report(count == 2, "sdp_subsession_count");
    report(video, "sdp_video_h264");
    report(audio, "sdp_audio_aac");
    Medium::close(s);
  }
  {  // MIKEY round trip
    MIKEYState* a = MIKEYState::createNew(True);
    unsigned size = 0;
    u_int8_t* msg = a->generateMessage(size);
    MIKEYState* b = MIKEYState::createNew(msg, size);
    report(b != NULL && b->encryptSRTP() == a->encryptSRTP() && memcmp(b->keyData(), a->keyData(), 30) == 0
           && b->MKI() == a->MKI(), "mikey_roundtrip");
    report(MIKEYState::createNew(msg, size / 2) == NULL, "mikey_rejects_truncated");
    delete[] msg; delete a; delete b;
  }
  printf("%d failure(s)\n", failures);
  return failures == 0 ? 0 : 1;
}
