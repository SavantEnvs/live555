// MPEG-2 Transport Stream demultiplexer (as in testMPEG2TransportStreamSplitter): PAT/PMT/PES
// parsing in MPEG2TransportStreamParser*. Input is a .ts byte stream. The demux writes each
// elementary stream it finds to a file in the cwd, so the process runs in a private scratch dir.
// The input is fed through FuzzStallingSource (see fuzz_common.hh for why).
#include "fuzz_common.hh"

static void afterReading(void*) {}

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  if (chdir(fuzzScratchDir()) != 0) { perror("chdir"); abort(); }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  UsageEnvironment* env = fuzzEnv();
  EventLoopWatchVariable exhausted(0);
  FuzzStallingSource* src = FuzzStallingSource::createNew(*env, data, size, &exhausted);
  MPEG2TransportStreamDemux* demux = MPEG2TransportStreamDemux::createNew(*env, src, afterReading, NULL);
  env->taskScheduler().doEventLoop(&exhausted);
  Medium::close(demux);
  Medium::close(src); // the parser does not own its input source
  return 0;
}
