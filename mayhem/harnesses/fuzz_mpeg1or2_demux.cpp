// MPEG-1/2 Program Stream demultiplexer (pack / system / PES headers) feeding the MPEG video and
// audio elementary-stream framers, as in testMPEG1or2Splitter and the RTSP server's .mpg support.
#include "fuzz_common.hh"

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  UsageEnvironment* env = fuzzEnv();
  ByteStreamFileSource* src = fuzzFileSource("input.mpg", data, size);
  MPEG1or2Demux* demux = MPEG1or2Demux::createNew(*env, src, False);
  FramedSource* video = MPEG1or2VideoStreamFramer::createNew(*env, demux->newVideoStream());
  FramedSource* audio = MPEG1or2AudioStreamFramer::createNew(*env, demux->newAudioStream());
  DrainGroup g = {2, 0};
  DrainSink* vs = DrainSink::createNew(*env);
  DrainSink* as = DrainSink::createNew(*env);
  vs->startPlaying(*video, drainGroupAfterPlaying, &g);
  as->startPlaying(*audio, drainGroupAfterPlaying, &g);
  env->taskScheduler().doEventLoop(&g.done);
  Medium::close(vs);
  Medium::close(as);
  Medium::close(video);
  Medium::close(audio);
  Medium::close(demux); // also closes src
  return 0;
}
