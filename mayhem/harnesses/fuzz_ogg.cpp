// Ogg demuxer (OggFileParser: page parsing plus Vorbis/Theora/Opus identification headers), as
// live555MediaServer serves .ogg/.ogv/.opus files and testOggStreamer streams them: parse the
// headers, open a demux, read every track through the streaming filter chain until end of file.
#include "fuzz_common.hh"

static OggFile* gFile;
static EventLoopWatchVariable gCreated;
static void onCreation(OggFile* f, void*) { gFile = f; gCreated = 1; }

enum { kMaxTracks = 16 };

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  UsageEnvironment* env = fuzzEnv();
  char const* path = fuzzWriteFile("input.ogg", data, size);
  gFile = NULL; gCreated = 0;
  OggFile::createNew(*env, path, onCreation, NULL);
  env->taskScheduler().doEventLoop(&gCreated);
  if (gFile == NULL) return 0;

  OggDemux* demux = gFile->newDemux();
  FramedSource* sources[kMaxTracks] = {NULL};
  DrainSink* sinks[kMaxTracks] = {NULL};
  DrainGroup g = {0, 0};
  unsigned n = gFile->numTracks();
  if (n > kMaxTracks) n = kMaxTracks;
  for (unsigned i = 0; i < n; ++i) {
    u_int32_t trackNumber = 0;
    FramedSource* base = demux->newDemuxedTrack(trackNumber);
    if (base == NULL) break;
    unsigned estBitrate, numFilters;
    sources[i] = gFile->createSourceForStreaming(base, trackNumber, estBitrate, numFilters);
    if (sources[i] == NULL) { Medium::close(base); continue; }
    sinks[i] = DrainSink::createNew(*env);
    ++g.pending;
  }
  if (g.pending > 0) {
    for (unsigned i = 0; i < n; ++i) {
      if (sinks[i] != NULL) sinks[i]->startPlaying(*sources[i], drainGroupAfterPlaying, &g);
    }
    env->taskScheduler().doEventLoop(&g.done);
  }
  for (unsigned i = 0; i < n; ++i) {
    if (sinks[i] != NULL) sinks[i]->stopPlaying();
    Medium::close(sources[i]);
  }
  for (unsigned i = 0; i < n; ++i) Medium::close(sinks[i]);
  Medium::close(gFile);
  return 0;
}
