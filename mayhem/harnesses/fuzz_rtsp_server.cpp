// RTSP server request handling, over a real loopback TCP connection — the bytes a remote client
// sends to live555MediaServer. The server is mediaServer's own DynamicRTSPServer (compiled into this
// harness unmodified), which maps stream names to files in its cwd; the cwd is a private scratch dir
// holding one small WAV file ("test.wav"), so DESCRIBE/SETUP/PLAY can reach the on-demand
// subsession code. Reaches RTSPServer.cpp request parsing (Content-Length, Require, CSeq, Session,
// Transport, Range...), RTSPCommon.cpp, RTSP-over-HTTP tunneling, interleaved '$' framing,
// GenericMediaServer and OnDemandServerMediaSubsession.
//
// Input byte 0, bit 0: protect the server with a Digest authentication database (user "user",
// password "pass"), so the Authorization header parser is reachable. The remaining bytes are
// written to the server; the harness then half-closes the connection and pumps the event loop
// until the server closes its side. A fresh server is created and closed for every input, so no
// session state survives from one input to the next.
#include "fuzz_common.hh"
#include "../../mediaServer/DynamicRTSPServer.hh"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static void writeWavFixture() {
  // 1 second of 8 kHz, 8-bit, mono PCM.
  unsigned const dataSize = 8000;
  unsigned char hdr[44];
  memcpy(hdr, "RIFF", 4);
  unsigned riffSize = 36 + dataSize;
  for (int i = 0; i < 4; ++i) hdr[4 + i] = (riffSize >> (8 * i)) & 0xFF;
  memcpy(hdr + 8, "WAVEfmt ", 8);
  unsigned char const fmt[20] = {16, 0, 0, 0, 1, 0, 1, 0, 0x40, 0x1F, 0, 0, 0x40, 0x1F, 0, 0, 1, 0, 8, 0};
  memcpy(hdr + 16, fmt, 20);
  memcpy(hdr + 36, "data", 4);
  for (int i = 0; i < 4; ++i) hdr[40 + i] = (dataSize >> (8 * i)) & 0xFF;
  FILE* f = fopen("test.wav", "wb");
  if (f == NULL) { perror("fopen test.wav"); abort(); }
  fwrite(hdr, 1, sizeof hdr, f);
  for (unsigned i = 0; i < dataSize; ++i) fputc(0x80 + (i % 32), f);
  fclose(f);
}

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  if (chdir(fuzzScratchDir()) != 0) { perror("chdir"); abort(); }
  writeWavFixture();
  return 0;
}

struct Client {
  int sock;
  uint8_t const* data;
  size_t remaining;
  EventLoopWatchVariable done;
};

static void clientHandler(void* clientData, int mask) {
  Client* c = (Client*)clientData;
  UsageEnvironment* env = fuzzEnv();
  if (mask & SOCKET_WRITABLE) {
    ssize_t n = 0;
    if (c->remaining > 0) n = send(c->sock, c->data, c->remaining, MSG_NOSIGNAL);
    if (c->remaining == 0) {
      // nothing (left) to send
    } else if (n > 0) {
      c->data += n;
      c->remaining -= (size_t)n;
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
      c->done = 1; // the server closed the connection before reading everything
      return;
    }
    if (c->remaining == 0) {
      shutdown(c->sock, SHUT_WR);
      env->taskScheduler().setBackgroundHandling(c->sock, SOCKET_READABLE | SOCKET_EXCEPTION,
                                                 clientHandler, c);
    }
  }
  if (mask & (SOCKET_READABLE | SOCKET_EXCEPTION)) {
    char buf[65536];
    ssize_t n = recv(c->sock, buf, sizeof buf, 0);
    if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) c->done = 1;
  }
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  if (size < 1) return -1;
  UsageEnvironment* env = fuzzEnv();

  UserAuthenticationDatabase* authDB = NULL;
  if (data[0] & 1) {
    authDB = new UserAuthenticationDatabase("LIVE555 Streaming Media");
    authDB->addUserRecord("user", "pass");
  }
  // reclamationSeconds 0: no liveness timers; every session is destroyed with the server below.
  RTSPServer* server = DynamicRTSPServer::createNew(*env, Port(0), authDB, 0);
  if (server == NULL) { fprintf(stderr, "RTSP server: %s\n", env->getResultMsg()); abort(); }

  char* prefix = server->rtspURLPrefix(); // "rtsp://<addr>:<port>/"
  char* colon = strrchr(prefix, ':');
  int port = colon != NULL ? atoi(colon + 1) : 0;
  delete[] prefix;
  if (port <= 0) abort();

  Client c;
  c.sock = socket(AF_INET, SOCK_STREAM, 0);
  if (c.sock < 0) { perror("socket"); abort(); }
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  // Non-blocking connect: it completes from the event loop (the socket becomes writable), and a
  // signal cannot interrupt it.
  fcntl(c.sock, F_SETFL, fcntl(c.sock, F_GETFL) | O_NONBLOCK);
  if (connect(c.sock, (struct sockaddr*)&addr, sizeof addr) != 0 && errno != EINPROGRESS && errno != EINTR) {
    perror("connect"); abort();
  }
  c.data = data + 1;
  c.remaining = size - 1;
  c.done = 0;
  env->taskScheduler().setBackgroundHandling(c.sock, SOCKET_READABLE | SOCKET_WRITABLE | SOCKET_EXCEPTION,
                                             clientHandler, &c);
  env->taskScheduler().doEventLoop(&c.done);

  env->taskScheduler().disableBackgroundHandling(c.sock);
  close(c.sock);
  Medium::close(server);
  delete authDB;
  return 0;
}
