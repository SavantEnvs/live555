// Shared helpers for the live555 libFuzzer harnesses.
//
// live555 is event-loop driven: one BasicTaskScheduler + BasicUsageEnvironment per process (kept
// across inputs on purpose; it holds no input-derived state once every Medium created for an input
// has been closed). Each input builds its own source/parser/sink chain, runs the event loop until
// the chain reports closure (a watch variable), and closes every object it created.
#ifndef LIVE555_FUZZ_COMMON_HH
#define LIVE555_FUZZ_COMMON_HH

#include <liveMedia.hh>
#include <BasicUsageEnvironment.hh>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static UsageEnvironment* fuzzEnv() {
  static UsageEnvironment* env = NULL;
  if (env == NULL) {
    TaskScheduler* scheduler = BasicTaskScheduler::createNew();
    env = BasicUsageEnvironment::createNew(*scheduler);
  }
  return env;
}

// A private scratch directory under $TMPDIR (default /tmp), created once per process.
static char const* fuzzScratchDir() {
  static char dir[512] = {0};
  if (dir[0] == '\0') {
    char const* tmp = getenv("TMPDIR");
    if (tmp == NULL || tmp[0] == '\0') tmp = "/tmp";
    snprintf(dir, sizeof dir, "%s/live555fuzzXXXXXX", tmp);
    if (mkdtemp(dir) == NULL) { perror("mkdtemp"); abort(); }
  }
  return dir;
}

// Writes the input to <scratch>/<name> (overwritten per input) and returns the path.
static char const* fuzzWriteFile(char const* name, uint8_t const* data, size_t size) {
  static char path[1024];
  snprintf(path, sizeof path, "%s/%s", fuzzScratchDir(), name);
  FILE* f = fopen(path, "wb");
  if (f == NULL) { perror("fopen"); abort(); }
  if (size > 0 && fwrite(data, 1, size, f) != size) { perror("fwrite"); abort(); }
  fclose(f);
  return path;
}

// The input as a byte-stream file source, the way the media server and the test programs read
// media. (ByteStreamFileSource delivers from the event loop; ByteStreamMemoryBufferSource reports
// end-of-stream synchronously from inside getNextFrame(), which several parsers do not expect and
// which no live555 application does.)
static ByteStreamFileSource* fuzzFileSource(char const* name, uint8_t const* data, size_t size) {
  ByteStreamFileSource* src = ByteStreamFileSource::createNew(*fuzzEnv(), fuzzWriteFile(name, data, size));
  if (src == NULL) { fprintf(stderr, "cannot open %s\n", name); abort(); }
  return src;
}

// A source that delivers the input (in chunks of at most the reader's buffer size, each from the
// event loop like a file read) and, once it is exhausted, signals `exhausted` instead of closing.
// Used where the parser's own end-of-stream handling cannot be survived by a caller that keeps
// running (MPEG2TransportStreamDemux deletes itself, and with it the parser that is still on the
// stack, when its source closes; upstream's splitter exit()s in that callback). The harness then
// closes the chain itself once everything delivered has been parsed.
class FuzzStallingSource: public FramedSource {
public:
  static FuzzStallingSource* createNew(UsageEnvironment& env, uint8_t const* data, size_t size,
                                       EventLoopWatchVariable* exhausted) {
    return new FuzzStallingSource(env, data, size, exhausted);
  }

protected:
  FuzzStallingSource(UsageEnvironment& env, uint8_t const* data, size_t size, EventLoopWatchVariable* exhausted)
    : FramedSource(env), fBuf(new uint8_t[size > 0 ? size : 1]), fSize(size), fPos(0),
      fExhausted(exhausted), fTask(NULL) {
    if (size > 0) memcpy(fBuf, data, size);
  }
  virtual ~FuzzStallingSource() {
    envir().taskScheduler().unscheduleDelayedTask(fTask);
    delete[] fBuf;
  }

  virtual void doGetNextFrame() {
    if (fPos >= fSize) { *fExhausted = 1; return; } // never closes: the harness ends the loop
    fTask = envir().taskScheduler().scheduleDelayedTask(0, deliver, this);
  }
  virtual void doStopGettingFrames() {
    envir().taskScheduler().unscheduleDelayedTask(fTask);
    fTask = NULL;
  }

private:
  static void deliver(void* clientData) {
    FuzzStallingSource* src = (FuzzStallingSource*)clientData;
    src->fTask = NULL;
    size_t n = src->fSize - src->fPos;
    if (n > src->fMaxSize) n = src->fMaxSize;
    memcpy(src->fTo, src->fBuf + src->fPos, n);
    src->fPos += n;
    src->fFrameSize = (unsigned)n;
    src->fNumTruncatedBytes = 0;
    gettimeofday(&src->fPresentationTime, NULL);
    FramedSource::afterGetting(src);
  }

  uint8_t* fBuf;
  size_t fSize, fPos;
  EventLoopWatchVariable* fExhausted;
  TaskToken fTask;
};

// A sink that pulls every frame from its source and discards it. Each next read is scheduled as a
// zero-delay task so a synchronously-delivering source cannot recurse without bound.
class DrainSink: public MediaSink {
public:
  static DrainSink* createNew(UsageEnvironment& env) { return new DrainSink(env); }

protected:
  DrainSink(UsageEnvironment& env): MediaSink(env), fTask(NULL) {}
  virtual ~DrainSink() { envir().taskScheduler().unscheduleDelayedTask(fTask); }

  virtual Boolean continuePlaying() {
    if (fSource == NULL) return False;
    fSource->getNextFrame(fBuf, sizeof fBuf, afterGettingFrame, this, onSourceClosure, this);
    return True;
  }

private:
  static void afterGettingFrame(void* clientData, unsigned, unsigned, struct timeval, unsigned) {
    DrainSink* sink = (DrainSink*)clientData;
    sink->fTask = sink->envir().taskScheduler().scheduleDelayedTask(0, readNext, sink);
  }
  static void readNext(void* clientData) {
    DrainSink* sink = (DrainSink*)clientData;
    sink->fTask = NULL;
    sink->continuePlaying();
  }

  TaskToken fTask;
  unsigned char fBuf[200000];
};

// Counts finished sinks for one input; the event loop stops once all are done.
struct DrainGroup {
  unsigned pending;
  EventLoopWatchVariable done;
};

static void drainGroupAfterPlaying(void* clientData) {
  DrainGroup* g = (DrainGroup*)clientData;
  if (g->pending > 0) --g->pending;
  if (g->pending == 0) g->done = 1;
}

#endif
