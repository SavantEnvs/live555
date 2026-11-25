// RTP and RTCP packets arriving over UDP — what any peer on a receiving client's media sockets can
// send. A fixed SDP (the kind an RTSP client receives from DESCRIBE) is parsed and every subsession
// initiate()d, exactly as openRTSP does: that creates, per m= line, the RTP/RTCP Groupsocks bound to
// ephemeral UDP ports, the codec's RTP source and an RTCPInstance. Each subsession's readSource() is
// drained by a sink, so MultiFramedRTPSource::networkReadHandler1 and the payload formats'
// processSpecialHeader/frame reassembly run on every packet, and RTCPInstance::incomingReportHandler1
// parses the RTCP ones (SR/RR/SDES/BYE/APP/RTPFB/PSFB, compound packets).
//
// Input: a sequence of records [selector][len hi][len lo][len bytes]. selector % (2 * #subsessions)
// picks the subsession and whether the bytes go to its RTP (even) or RTCP (odd) port. Every record
// is sent from one loopback UDP socket as one datagram; the harness then pumps the event loop until
// every receiving socket has been read empty, or until no socket has been read for a while (a source
// that stopped reading), and closes the session. The session is new for every input.
#include "fuzz_common.hh"

#include <errno.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static char const kSDP[] =
  "v=0\r\n"
  "o=- 1 1 IN IP4 127.0.0.1\r\n"
  "s=fuzz\r\n"
  "c=IN IP4 0.0.0.0\r\n"
  "t=0 0\r\n"
  "m=video 0 RTP/AVP 96\r\n"
  "a=rtpmap:96 H264/90000\r\n"
  "a=fmtp:96 packetization-mode=1;sprop-parameter-sets=Z0IAKeKQFAe2AtwEBAaQeJEV,aM48gA==\r\n"
  "m=video 0 RTP/AVP 97\r\n"
  "a=rtpmap:97 H265/90000\r\n"
  "a=fmtp:97 sprop-max-don-diff=1\r\n"
  "m=audio 0 RTP/AVP 98\r\n"
  "a=rtpmap:98 MPEG4-GENERIC/44100/2\r\n"
  "a=fmtp:98 streamtype=5;profile-level-id=15;mode=AAC-hbr;config=1210;sizeLength=13;indexLength=3;indexDeltaLength=3\r\n"
  "m=video 0 RTP/AVP 26\r\n"
  "m=video 0 RTP/AVP 99\r\n"
  "a=rtpmap:99 X-QT/90000\r\n"
  "m=video 0 RTP/AVP 100\r\n"
  "a=rtpmap:100 VP8/90000\r\n"
  "m=video 0 RTP/AVP 101\r\n"
  "a=rtpmap:101 MP4V-ES/90000\r\n"
  "m=audio 0 RTP/AVP 102\r\n"
  "a=rtpmap:102 MPA-ROBUST/90000\r\n"
  "m=audio 0 RTP/AVP 103\r\n"
  "a=rtpmap:103 MP4A-LATM/90000\r\n"
  "a=fmtp:103 cpresent=0;config=400024203fc0\r\n"
  "m=audio 0 RTP/AVP 104\r\n"
  "a=rtpmap:104 AMR/8000\r\n"
  "a=fmtp:104 octet-align=1\r\n"
  "m=video 0 RTP/AVP 105\r\n"
  "a=rtpmap:105 THEORA/90000\r\n"
  "m=audio 0 RTP/AVP 106\r\n"
  "a=rtpmap:106 AC3/48000\r\n"
  "m=video 0 RTP/AVP 107\r\n"
  "a=rtpmap:107 VP9/90000\r\n"
  "m=video 0 RTP/AVP 33\r\n";

enum { kMaxSubs = 32 };
static int gSender = -1;

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  gSender = socket(AF_INET, SOCK_DGRAM, 0);
  if (gSender < 0) { perror("socket"); abort(); }
  return 0;
}

struct Pump {
  int socks[2 * kMaxSubs];
  unsigned numSocks;
  unsigned idle;
  int lastPending;
  TaskToken task;
  EventLoopWatchVariable done;
};

static int pendingBytes(Pump* p) {
  int total = 0;
  for (unsigned i = 0; i < p->numSocks; ++i) {
    int n = 0;
    if (ioctl(p->socks[i], FIONREAD, &n) == 0) total += n;
  }
  return total;
}

// Re-checks after every pass of the event loop (a zero-delay task runs once per select() round,
// after the sockets that select() found readable have been handled).
static void pumpCheck(void* clientData) {
  Pump* p = (Pump*)clientData;
  p->task = NULL;
  int pending = pendingBytes(p);
  if (pending == p->lastPending) ++p->idle; else p->idle = 0;
  p->lastPending = pending;
  if (pending == 0 || p->idle >= 64) { p->done = 1; return; }
  p->task = fuzzEnv()->taskScheduler().scheduleDelayedTask(0, pumpCheck, p);
}

static int localPort(int sock) {
  struct sockaddr_in a;
  socklen_t len = sizeof a;
  if (getsockname(sock, (struct sockaddr*)&a, &len) != 0) return 0;
  return ntohs(a.sin_port);
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  UsageEnvironment* env = fuzzEnv();
  MediaSession* session = MediaSession::createNew(*env, kSDP);
  if (session == NULL) { fprintf(stderr, "SDP: %s\n", env->getResultMsg()); abort(); }

  MediaSubsession* subs[kMaxSubs];
  DrainSink* sinks[kMaxSubs];
  int rtpPort[kMaxSubs], rtcpPort[kMaxSubs];
  unsigned numSubs = 0;
  DrainGroup group = {0, 0};
  Pump p;
  memset(&p, 0, sizeof p);
  p.lastPending = -1;

  MediaSubsessionIterator iter(*session);
  MediaSubsession* sub;
  while ((sub = iter.next()) != NULL && numSubs < kMaxSubs) {
    if (!sub->initiate()) { fprintf(stderr, "initiate %s: %s\n", sub->codecName(), env->getResultMsg()); abort(); }
    subs[numSubs] = sub;
    rtpPort[numSubs] = localPort(sub->rtpSource()->RTPgs()->socketNum());
    p.socks[p.numSocks++] = sub->rtpSource()->RTPgs()->socketNum();
    rtcpPort[numSubs] = 0;
    if (sub->rtcpInstance() != NULL && sub->rtcpInstance()->RTCPgs() != NULL) {
      int s = sub->rtcpInstance()->RTCPgs()->socketNum();
      rtcpPort[numSubs] = localPort(s);
      p.socks[p.numSocks++] = s;
    }
    sinks[numSubs] = DrainSink::createNew(*env);
    ++group.pending;
    sinks[numSubs]->startPlaying(*sub->readSource(), drainGroupAfterPlaying, &group);
    ++numSubs;
  }

  struct sockaddr_in to;
  memset(&to, 0, sizeof to);
  to.sin_family = AF_INET;
  to.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  size_t pos = 0;
  while (pos + 3 <= size) {
    unsigned sel = data[pos] % (2 * numSubs);
    size_t len = ((size_t)data[pos + 1] << 8) | data[pos + 2];
    pos += 3;
    if (len > size - pos) len = size - pos;
    int port = (sel & 1) ? rtcpPort[sel / 2] : rtpPort[sel / 2];
    if (port != 0) {
      to.sin_port = htons(port);
      (void)sendto(gSender, data + pos, len, 0, (struct sockaddr*)&to, sizeof to);
    }
    pos += len;
  }

  p.task = env->taskScheduler().scheduleDelayedTask(0, pumpCheck, &p);
  env->taskScheduler().doEventLoop(&p.done);
  env->taskScheduler().unscheduleDelayedTask(p.task);

  for (unsigned i = 0; i < numSubs; ++i) {
    sinks[i]->stopPlaying();
    Medium::close(sinks[i]);
  }
  Medium::close(session); // closes every subsession's RTCP instance, RTP source and sockets
  return 0;
}
