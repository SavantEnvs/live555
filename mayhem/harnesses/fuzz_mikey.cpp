// MIKEY (RFC 3830) binary message parser: the payload of an SDP "a=key-mgmt:mikey" attribute
// sent by a remote peer. Entry point: MIKEYState::createNew(message, size); a parsed state is
// re-serialized with generateMessage().
#include <liveMedia.hh>
#include <stdint.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size) {
  // Exact-size heap copy, so ASan sees any read past the message end.
  u_int8_t* msg = new u_int8_t[size > 0 ? size : 1];
  if (size > 0) memcpy(msg, data, size);
  MIKEYState* state = MIKEYState::createNew(msg, (unsigned)size);
  if (state != NULL) {
    unsigned outSize = 0;
    u_int8_t* out = state->generateMessage(outSize);
    delete[] out;
    delete state;
  }
  delete[] msg;
  return 0;
}
