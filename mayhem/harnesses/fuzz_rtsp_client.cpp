// RTSP client response handling — the bytes an RTSP server sends back to openRTSP / proxyServer.
// A loopback TCP listener plays the server: it accepts the RTSPClient's connection, writes the
// input as the server's whole reply stream, half-closes, and discards whatever the client sends.
// The client runs the same command chain openRTSP does: DESCRIBE → (SDP → MediaSession, initiate the
// first subsession) → SETUP → PLAY → GET_PARAMETER → TEARDOWN, each step started from the previous
// step's response handler. Reaches RTSPClient::handleResponseBytes (status line, CSeq matching,
// Content-Length bodies, interleaved '$' data, server-to-client requests), parseResponseCode,
// parseTransportParams, parseRTPInfoParams, parseScaleParam/parseRangeParam, the Digest/Basic
// WWW-Authenticate handling (the client carries credentials, so a 401 is retried), MediaSession SDP
// parsing and subsession initiation.
//
// The input is done when the chain ends (a step fails, at the latest when the listener's EOF reaches
// the client and every pending request is failed with REQ_FAIL_CONNECTION_CLOSED) or when the client
// closes the connection. A fresh client and a
// fresh accepted connection are used for every input; only the listening socket is kept.
#include "fuzz_common.hh"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

static int gListenSock = -1;
static int gListenPort = 0;

extern "C" int LLVMFuzzerInitialize(int*, char***) {
  gListenSock = socket(AF_INET, SOCK_STREAM, 0);
  if (gListenSock < 0) { perror("socket"); abort(); }
  int one = 1;
  setsockopt(gListenSock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof addr);
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind(gListenSock, (struct sockaddr*)&addr, sizeof addr) != 0) { perror("bind"); abort(); }
  if (listen(gListenSock, 16) != 0) { perror("listen"); abort(); }
  socklen_t len = sizeof addr;
  getsockname(gListenSock, (struct sockaddr*)&addr, &len);
  gListenPort = ntohs(addr.sin_port);
  fcntl(gListenSock, F_SETFL, fcntl(gListenSock, F_GETFL) | O_NONBLOCK);
  return 0;
}

struct Run {
  uint8_t const* data;
  size_t remaining;
  int peer;            // the first accepted connection, which is served the input
  int extraPeers[8];   // any further connections (e.g. a reconnect after a redirect): closed at once
  unsigned numExtra;
  MediaSession* session;
  EventLoopWatchVariable done;
};
static Run* gRun = NULL;

static void peerHandler(void* clientData, int mask) {
  Run* r = (Run*)clientData;
  UsageEnvironment* env = fuzzEnv();
  if ((mask & SOCKET_WRITABLE) && r->remaining > 0) {
    ssize_t n = send(r->peer, r->data, r->remaining, MSG_NOSIGNAL);
    if (n > 0) {
      r->data += n;
      r->remaining -= (size_t)n;
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
      r->remaining = 0; // the client closed; stop writing
    }
    if (r->remaining == 0) {
      shutdown(r->peer, SHUT_WR);
      env->taskScheduler().setBackgroundHandling(r->peer, SOCKET_READABLE | SOCKET_EXCEPTION, peerHandler, r);
    }
  }
  if (mask & (SOCKET_READABLE | SOCKET_EXCEPTION)) {
    char buf[65536];
    ssize_t n = recv(r->peer, buf, sizeof buf, 0);
    if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
      // The client closed the connection: it has nothing left to read, so the input is consumed.
      // (Needed besides the handler chain: a response whose CSeq is newer than a pending request
      // makes RTSPClient drop that request as unanswered without ever calling its handler.)
      env->taskScheduler().disableBackgroundHandling(r->peer);
      r->done = 1;
    }
  }
}

static void acceptHandler(void* clientData, int) {
  Run* r = (Run*)clientData;
  UsageEnvironment* env = fuzzEnv();
  for (;;) {
    int s = accept(gListenSock, NULL, NULL);
    if (s < 0) return;
    fcntl(s, F_SETFL, fcntl(s, F_GETFL) | O_NONBLOCK);
    if (r->peer < 0) {
      r->peer = s;
      int mask = SOCKET_READABLE | SOCKET_EXCEPTION | (r->remaining > 0 ? SOCKET_WRITABLE : 0);
      if (r->remaining == 0) shutdown(s, SHUT_WR);
      env->taskScheduler().setBackgroundHandling(s, mask, peerHandler, r);
    } else if (r->numExtra < sizeof r->extraPeers / sizeof r->extraPeers[0]) {
      shutdown(s, SHUT_RDWR);
      r->extraPeers[r->numExtra++] = s;
    } else {
      close(s);
    }
  }
}

static void finish() { gRun->done = 1; }

static void afterTeardown(RTSPClient*, int, char* resultString) {
  delete[] resultString;
  finish();
}

static void afterGetParameter(RTSPClient* client, int resultCode, char* resultString) {
  delete[] resultString;
  if (resultCode != 0 || gRun->session == NULL) { finish(); return; }
  client->sendTeardownCommand(*gRun->session, afterTeardown);
}

static void afterPlay(RTSPClient* client, int resultCode, char* resultString) {
  delete[] resultString;
  if (resultCode != 0) { finish(); return; }
  client->sendGetParameterCommand(*gRun->session, afterGetParameter, "position");
}

static void afterSetup(RTSPClient* client, int resultCode, char* resultString) {
  delete[] resultString;
  if (resultCode != 0) { finish(); return; }
  client->sendPlayCommand(*gRun->session, afterPlay, 0.0, -1.0, 1.0);
}

static void afterDescribe(RTSPClient* client, int resultCode, char* resultString) {
  if (resultCode != 0 || resultString == NULL) { delete[] resultString; finish(); return; }
  gRun->session = MediaSession::createNew(*fuzzEnv(), resultString);
  delete[] resultString;
  if (gRun->session == NULL) { finish(); return; }
  MediaSubsessionIterator iter(*gRun->session);
  MediaSubsession* sub = iter.next();
  // openRTSP's -t: RTP-over-TCP, so SETUP does not depend on opening UDP ports for the stream.
  if (sub == NULL || !sub->initiate()) { finish(); return; }
  client->sendSetupCommand(*sub, afterSetup, False, True /*streamUsingTCP*/);
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  UsageEnvironment* env = fuzzEnv();
  Run r;
  memset(&r, 0, sizeof r);
  r.data = data;
  r.remaining = size;
  r.peer = -1;
  gRun = &r;

  env->taskScheduler().setBackgroundHandling(gListenSock, SOCKET_READABLE, acceptHandler, &r);

  char url[64];
  snprintf(url, sizeof url, "rtsp://127.0.0.1:%d/stream", gListenPort);
  RTSPClient* client = RTSPClient::createNew(*env, url, 0, "fuzz");
  if (client == NULL) { fprintf(stderr, "RTSPClient: %s\n", env->getResultMsg()); abort(); }
  Authenticator auth("user", "pass");
  client->sendDescribeCommand(afterDescribe, &auth);
  env->taskScheduler().doEventLoop(&r.done);

  env->taskScheduler().disableBackgroundHandling(gListenSock);
  // Session first, as testRTSPClient's shutdown does: with RTP-over-TCP its RTPInterfaces still
  // reference the client's socket, which closing the client first would free under them.
  if (r.session != NULL) Medium::close(r.session);
  Medium::close(client);
  if (r.peer >= 0) {
    env->taskScheduler().disableBackgroundHandling(r.peer);
    close(r.peer);
  }
  for (unsigned i = 0; i < r.numExtra; ++i) close(r.extraPeers[i]);
  // Drain any connection still queued on the listener, so it cannot be served to the next input.
  for (int s; (s = accept(gListenSock, NULL, NULL)) >= 0;) close(s);
  gRun = NULL;
  return 0;
}
