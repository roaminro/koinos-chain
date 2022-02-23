#include "includes/chain_wrapper.hpp"

using namespace boost;
using namespace koinos;

void set_block_merkle_roots(protocol::block &block, crypto::multicodec code, crypto::digest_size size = crypto::digest_size(0))
{
    std::vector<crypto::multihash> hashes;
    hashes.reserve(block.transactions().size() * 2);

    for (const auto &trx : block.transactions())
    {
        hashes.emplace_back(crypto::hash(code, trx.header(), size));
        hashes.emplace_back(crypto::hash(code, trx.signatures(), size));
    }

    auto transaction_merkle_tree = crypto::merkle_tree(code, hashes);
    block.mutable_header()->set_transaction_merkle_root(util::converter::as<std::string>(transaction_merkle_tree.root()->hash()));
}

void sign_block(protocol::block &block, crypto::private_key &block_signing_key)
{
    auto id_mh = crypto::hash(crypto::multicodec::sha2_256, block.header());
    block.set_signature(util::converter::as<std::string>(block_signing_key.sign_compact(id_mh)));
}

void set_transaction_merkle_roots(protocol::transaction &transaction, crypto::multicodec code, crypto::digest_size size = crypto::digest_size(0))
{
    std::vector<crypto::multihash> operations;
    operations.reserve(transaction.operations().size());

    for (const auto &op : transaction.operations())
    {
        operations.emplace_back(crypto::hash(code, op, size));
    }

    auto operation_merkle_tree = crypto::merkle_tree(code, operations);
    transaction.mutable_header()->set_operation_merkle_root(util::converter::as<std::string>(operation_merkle_tree.root()->hash()));
}

void sign_transaction(protocol::transaction &transaction, crypto::private_key &transaction_signing_key)
{
    auto id_mh = crypto::hash(crypto::multicodec::sha2_256, transaction.header());
    transaction.set_id(util::converter::as<std::string>(id_mh));
    transaction.add_signatures(util::converter::as<std::string>(transaction_signing_key.sign_compact(id_mh)));
}

Napi::Object ChainWrapper::Init(Napi::Env env, Napi::Object exports)
{
    Napi::Function func =
        DefineClass(env,
                    "Chain",
                    {InstanceMethod("getHeadInfo", &ChainWrapper::GetHeadInfo),
                     InstanceMethod("submitBlock", &ChainWrapper::SubmitBlock),
                     InstanceMethod("signTransaction", &ChainWrapper::SignTransaction)});

    Napi::FunctionReference *constructor = new Napi::FunctionReference();
    *constructor = Napi::Persistent(func);
    env.SetInstanceData(constructor);

    exports.Set("Chain", func);
    return exports;
}

ChainWrapper::ChainWrapper(const Napi::CallbackInfo &info)
    : Napi::ObjectWrap<ChainWrapper>(info)
{
    Napi::Env env = info.Env();

    Napi::Object options = info[0].As<Napi::Object>();

    std::string basedir_option = options.Has("basedir") ? options.Get("basedir").ToString().Utf8Value() : "./";
    std::string statedir_option = options.Has("statedir") ? options.Get("statedir").ToString().Utf8Value() : STATEDIR_DEFAULT;
    bool reset = options.Has("reset") ? options.Get("reset").ToBoolean() : false;
    std::string genesis_json = options.Has("genesis_json") ? options.Get("genesis_json").ToString().Utf8Value() : "{}";
    int64_t read_compute_limit = options.Has("read_compute_limit") ? options.Get("read_compute_limit").ToNumber().Int64Value() : READ_COMPUTE_BANDWITH_LIMIT_DEFAULT;
    std::string instance_id = options.Has("instance_id") ? options.Get("instance_id").ToString().Utf8Value() : util::random_alphanumeric(5);
    std::string block_signing_wif = options.Has("block_signing_wif") ? options.Get("block_signing_wif").ToString().Utf8Value() : "5JY6DFyroXn3wthivhwXgpspAWbBoRrD49paoP6zWhDRAPcSSi4";
    std::string log_level = options.Has("log_level") ? options.Get("log_level").ToString().Utf8Value() : LOG_LEVEL_DEFAULT;

    auto basedir = std::filesystem::path(basedir_option);
    if (basedir.is_relative())
        basedir = std::filesystem::current_path() / basedir;

    auto statedir = std::filesystem::path(statedir_option);
    if (statedir.is_relative())
        statedir = basedir / util::service::chain / statedir;

    if (!std::filesystem::exists(statedir))
        std::filesystem::create_directories(statedir);

    koinos::initialize_logging(util::service::chain, instance_id, log_level, basedir / util::service::chain / "logs");

    chain::genesis_data genesis_data;
    google::protobuf::util::JsonParseOptions jpo;
    google::protobuf::util::JsonStringToMessage(genesis_json, &genesis_data, jpo);

    crypto::multihash chain_id = crypto::hash(crypto::multicodec::sha2_256, genesis_data);

    LOG(info) << "Chain ID: " << chain_id;

    this->_block_signing_private_key = crypto::private_key::from_wif(block_signing_wif);

    this->_controller = new chain::controller(read_compute_limit);
    this->_controller->open(statedir, genesis_data, reset);
}

ChainWrapper::~ChainWrapper()
{
    delete this->_controller;
}

Napi::Value ChainWrapper::GetHeadInfo(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();

    rpc::chain::get_head_info_request req;
    rpc::chain::get_head_info_response res;

    try
    {
        res = this->_controller->get_head_info(req);
    }
    catch (const koinos::exception &e)
    {
        LOG(error) << "koinos::exception: " << e.what();
    }
    catch (std::exception &e)
    {
        LOG(error) << "std::exception: " << e.what();
    }
    catch (...)
    {
        LOG(error) << "Unexpected error";
    }

    Napi::ArrayBuffer retbuf = Napi::ArrayBuffer::New(env, res.ByteSizeLong());
    res.SerializeToArray((void *)retbuf.Data(), res.ByteSizeLong());

    return retbuf;
}

Napi::Value ChainWrapper::SubmitBlock(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();

    Napi::ArrayBuffer args = info[0].As<Napi::ArrayBuffer>();

    rpc::chain::submit_block_request req;
    req.ParseFromArray((void *)args.Data(), args.ByteLength());

    if (req.block().header().timestamp() == 0)
    {
        req.mutable_block()->mutable_header()->set_timestamp(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    }

    auto head_info = this->_controller->get_head_info();

    req.mutable_block()->mutable_header()->set_height(head_info.head_topology().height() + 1);
    req.mutable_block()->mutable_header()->set_signer(this->_block_signing_private_key.get_public_key().to_address_bytes());
    req.mutable_block()->mutable_header()->set_previous_state_merkle_root(head_info.head_state_merkle_root());
    req.mutable_block()->mutable_header()->set_previous(head_info.head_topology().id());

    set_block_merkle_roots(*req.mutable_block(), crypto::multicodec::sha2_256);
    req.mutable_block()->set_id(util::converter::as<std::string>(crypto::hash(crypto::multicodec::sha2_256, req.block().header())));
    sign_block(*req.mutable_block(), this->_block_signing_private_key);

    rpc::chain::submit_block_response res;
    try
    {
        res = this->_controller->submit_block(req);
    }
    catch (const koinos::exception &e)
    {
        LOG(error) << "koinos::exception: " << e.what();
    }
    catch (std::exception &e)
    {
        LOG(error) << "std::exception: " << e.what();
    }
    catch (...)
    {
        LOG(error) << "Unexpected error";
    }

    Napi::ArrayBuffer retbuf = Napi::ArrayBuffer::New(env, res.ByteSizeLong());
    res.SerializeToArray((void *)retbuf.Data(), res.ByteSizeLong());

    return retbuf;
}

Napi::Value ChainWrapper::SignTransaction(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();

    Napi::Object args = info[0].As<Napi::Object>();

    Napi::ArrayBuffer tx_buf = args.Get("tx").As<Napi::ArrayBuffer>();
    std::string payer_wif = args.Has("payer") ? args.Get("payer").ToString().Utf8Value() : "";
    std::string payee_wif = args.Has("payee") ? args.Get("payee").ToString().Utf8Value() : "";

    koinos::crypto::private_key payer_private_key;
    koinos::crypto::private_key payee_private_key;

    koinos::protocol::transaction transaction;
    transaction.ParseFromArray((void *)tx_buf.Data(), tx_buf.ByteLength());

    if (payer_wif.size())
    {
        payer_private_key = crypto::private_key::from_wif(payer_wif);
        transaction.mutable_header()->set_payer(payer_private_key.get_public_key().to_address_bytes());
    }

    if (payee_wif.size())
    {
        payee_private_key = crypto::private_key::from_wif(payee_wif);
        transaction.mutable_header()->set_payee(payee_private_key.get_public_key().to_address_bytes());
    }

    // determine if payer or payee pays for the transaction
    bool use_payee_nonce = payee_wif.size() && payee_wif != payer_wif;

    // populate nonce
    koinos::rpc::chain::get_account_nonce_request req;
    auto address = use_payee_nonce ? payee_private_key.get_public_key().to_address_bytes() : payer_private_key.get_public_key().to_address_bytes();

    req.set_account(address);
    auto nonce = this->_controller->get_account_nonce(req).nonce();
    koinos::chain::value_type nonce_value;
    nonce_value.ParseFromString(util::converter::as<std::string>(nonce));
    nonce_value.set_uint64_value(nonce_value.uint64_value() + 1);

    transaction.mutable_header()->set_chain_id(this->_controller->get_chain_id().chain_id());
    transaction.mutable_header()->set_nonce(util::converter::as<std::string>(nonce_value));
    set_transaction_merkle_roots(transaction, koinos::crypto::multicodec::sha2_256);

    if (payer_wif.size())
    {
        sign_transaction(transaction, payer_private_key);
    }

    if (payee_wif.size())
    {
        sign_transaction(transaction, payee_private_key);
    }

    Napi::ArrayBuffer retbuf = Napi::ArrayBuffer::New(env, transaction.ByteSizeLong());
    transaction.SerializeToArray((void *)retbuf.Data(), transaction.ByteSizeLong());

    return retbuf;
}