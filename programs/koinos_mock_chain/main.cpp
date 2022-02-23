#include <napi.h>
#include "includes/chain_wrapper.hpp"

Napi::Object InitModule(Napi::Env env, Napi::Object exports) {
  return ChainWrapper::Init(env, exports);
}

NODE_API_MODULE(addon, InitModule)
