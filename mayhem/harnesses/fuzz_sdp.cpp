// SDP session description parser (what an RTSP client gets back from DESCRIBE, or a SIP peer
// sends): MediaSession::createNew parses every line/attribute (rtpmap, fmtp, range, key-mgmt ->
// MIKEY, ...); MediaSubsession::initiate() then builds the per-codec RTP source for each m= line.
#include "fuzz_common.hh"

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  UsageEnvironment* env = fuzzEnv();
  char* sdp = new char[size + 1];
  memcpy(sdp, data, size);
  sdp[size] = '\0';

  MediaSession* session = MediaSession::createNew(*env, sdp);
  if (session != NULL) {
    (void)session->absStartTime();
    (void)session->playStartTime();
    (void)session->playEndTime();
    MediaSubsessionIterator iter(*session);
    MediaSubsession* sub;
    while ((sub = iter.next()) != NULL) {
      (void)sub->mediumName();
      (void)sub->codecName();
      (void)sub->fmtp_config();
      (void)sub->rtpTimestampFrequency();
      // Bind only ephemeral loopback-safe ports: ignore the port the SDP asks for (an RTSP client
      // does the same unless told to honor it).
      sub->setClientPortNum(0);
      if (sub->initiate()) {
        (void)sub->readSource();
      }
    }
    Medium::close(session);
  }
  delete[] sdp;
  return 0;
}
