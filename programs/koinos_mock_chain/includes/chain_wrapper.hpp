#pragma once

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

#include <napi.h>

#include <google/protobuf/util/json_util.h>

#include <koinos/chain/constants.hpp>
#include <koinos/chain/controller.hpp>
#include <koinos/chain/state.hpp>
#include <koinos/chain/system_calls.hpp>

#include <koinos/crypto/multihash.hpp>
#include <koinos/crypto/elliptic.hpp>
#include <koinos/crypto/merkle_tree.hpp>

#include <koinos/exception.hpp>
#include <koinos/log.hpp>

#include <koinos/util/base58.hpp>
#include <koinos/util/conversion.hpp>
#include <koinos/util/options.hpp>
#include <koinos/util/random.hpp>
#include <koinos/util/services.hpp>

#define KOINOS_MAJOR_VERSION "0"
#define KOINOS_MINOR_VERSION "3"
#define KOINOS_PATCH_VERSION "0"

#define LOG_LEVEL_DEFAULT "info"
#define STATEDIR_DEFAULT "blockchain"
#define READ_COMPUTE_BANDWITH_LIMIT_DEFAULT 10'000'000

KOINOS_DECLARE_EXCEPTION(service_exception);
KOINOS_DECLARE_DERIVED_EXCEPTION(invalid_argument, service_exception);

using namespace boost;
using namespace koinos;

class ChainWrapper : public Napi::ObjectWrap<ChainWrapper>
{
public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    ChainWrapper(const Napi::CallbackInfo &info);
    ~ChainWrapper();

private:
    Napi::Value GetHeadInfo(const Napi::CallbackInfo &info);
    Napi::Value SubmitBlock(const Napi::CallbackInfo &info);
    Napi::Value SignTransaction(const Napi::CallbackInfo &info);

    koinos::chain::controller* _controller;
    koinos::crypto::private_key _block_signing_private_key;
    std::vector<koinos::protocol::transaction> _pending_transactions;
};