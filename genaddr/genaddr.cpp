#include <boost/python.hpp>
namespace python = boost::python;

#include <bitcoin/bitcoin.hpp>

const std::string seed(bc::deterministic_wallet& wallet)
{
    return wallet.seed();
}

bool set_master_public_key(
    bc::deterministic_wallet& wallet, const std::string& mpk)
{
    return wallet.set_master_public_key(
        bc::data_chunk(mpk.begin(), mpk.end()));
}

const std::string master_public_key(const bc::deterministic_wallet& wallet)
{
    const bc::data_chunk& mpk = wallet.master_public_key();
    return std::string(mpk.begin(), mpk.end());
}

const std::string generate_public_key(const bc::deterministic_wallet& wallet,
    size_t n)
{
    const bc::data_chunk pubkey = wallet.generate_public_key(n);
    return std::string(pubkey.begin(), pubkey.end());
}

const std::string generate_secret(const bc::deterministic_wallet& wallet,
    size_t n)
{
    const bc::secret_parameter secret = wallet.generate_secret(n);
    return std::string(secret.begin(), secret.end());
}

const std::string pubkey_to_address(const std::string& pubkey)
{
    bc::payment_address payaddr;
    set_public_key(payaddr, bc::data_chunk(pubkey.begin(), pubkey.end()));
    return payaddr.encoded();
}

BOOST_PYTHON_MODULE(_genaddr)
{
    using namespace boost::python;
    class_<bc::deterministic_wallet>("DeterministicWallet")
        .def("new_seed", &bc::deterministic_wallet::new_seed)
        .def("set_seed", &bc::deterministic_wallet::set_seed)
        .def("seed", seed)
        .def("set_master_public_key", set_master_public_key)
        .def("master_public_key", master_public_key)
        .def("generate_public_key", generate_public_key)
        .def("generate_secret", generate_secret)
    ;
    def("pubkey_to_address", pubkey_to_address);
}

