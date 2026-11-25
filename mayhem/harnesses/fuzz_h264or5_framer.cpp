// H.264 / H.265 Annex-B elementary streams (.264/.265 files served by live555MediaServer, or piped
// into testH264VideoStreamer/testH265VideoStreamer): ByteStreamFileSource → H264VideoStreamFramer or
// H265VideoStreamFramer, set up as H264/H265VideoFileServerMediaSubsession does
// (includeStartCodeInOutput False), drained by a sink until the framer closes at end of file.
// Reaches H264or5VideoStreamParser::parse (start-code scanning, NAL classification, SPS/VPS parsing
// for the frame rate, removeEmulationBytes, access-unit boundary detection).
//
// Input byte 0, bit 0: H.265 instead of H.264. The rest is the file. A fresh file source, framer and
// sink are used for every input.
//
// Known upstream hang: a NAL unit of zero bytes (one start code directly followed by another, e.g.
// 02 00 00 00 00 01 00 00 00 01 ...) makes parse() return a frame size of 0 without having asked its
// source for more data; MPEGVideoStreamFramer::continueReadProcessing() takes 0 to mean "waiting for
// input", but no read is outstanding, so the stream stalls forever with nothing scheduled. It is left
// unguarded on purpose: it is a finding (Mayhem reports it as a timeout).
#include "fuzz_common.hh"

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  if (size < 1) return -1;
  UsageEnvironment* env = fuzzEnv();
  Boolean const h265 = (data[0] & 1) != 0;
  ByteStreamFileSource* src = fuzzFileSource(h265 ? "in.265" : "in.264", data + 1, size - 1);
  FramedSource* framer = h265
    ? (FramedSource*)H265VideoStreamFramer::createNew(*env, src, False, False)
    : (FramedSource*)H264VideoStreamFramer::createNew(*env, src, False, False);
  DrainGroup group = {1, 0};
  DrainSink* sink = DrainSink::createNew(*env);
  sink->startPlaying(*framer, drainGroupAfterPlaying, &group);
  env->taskScheduler().doEventLoop(&group.done);
  sink->stopPlaying();
  Medium::close(sink);
  Medium::close(framer); // also closes the file source
  return 0;
}
