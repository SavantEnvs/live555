// Matroska / WebM demuxer (EBML + MatroskaFileParser), as live555MediaServer serves .mkv/.webm and
// testMKVSplitter splits them: parse the track headers, open a demux, read every chosen track
// through the streaming filter chain until end of file.
#include "fuzz_common.hh"

static MatroskaFile* gFile;
static EventLoopWatchVariable gCreated;
static void onCreation(MatroskaFile* f, void*) { gFile = f; gCreated = 1; }

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  UsageEnvironment* env = fuzzEnv();
  char const* path = fuzzWriteFile("input.mkv", data, size);
  gFile = NULL; gCreated = 0;
  MatroskaFile::createNew(*env, path, onCreation, NULL);
  env->taskScheduler().doEventLoop(&gCreated);
  if (gFile == NULL) return 0;

  MatroskaDemux* demux = gFile->newDemux();
  FramedSource* sources[3] = {NULL, NULL, NULL};
  DrainSink* sinks[3] = {NULL, NULL, NULL};
  DrainGroup g = {0, 0};
  for (unsigned i = 0; i < 3; ++i) {
    unsigned trackNumber = 0;
    FramedSource* base = demux->newDemuxedTrack(trackNumber);
    if (base == NULL) continue;
    unsigned estBitrate, numFilters;
    (void)gFile->trackMIMEType(trackNumber);
    sources[i] = gFile->createSourceForStreaming(base, trackNumber, estBitrate, numFilters);
    if (sources[i] == NULL) { Medium::close(base); continue; }
    sinks[i] = DrainSink::createNew(*env);
    ++g.pending;
  }
  if (g.pending > 0) {
    for (unsigned i = 0; i < 3; ++i) {
      if (sinks[i] != NULL) sinks[i]->startPlaying(*sources[i], drainGroupAfterPlaying, &g);
    }
    env->taskScheduler().doEventLoop(&g.done);
  }
  for (unsigned i = 0; i < 3; ++i) {
    if (sinks[i] != NULL) sinks[i]->stopPlaying();
    Medium::close(sources[i]);
  }
  for (unsigned i = 0; i < 3; ++i) Medium::close(sinks[i]);
  Medium::close(gFile); // also deletes a demux that has no tracks left open
  return 0;
}
