#include <boost/python.hpp>
#include <bitcoin/bitcoin.hpp>

bool validate_address(const std::string& addr)
{
    bc::payment_address payaddr;
    if (!payaddr.set_encoded(addr))
        return false;
    return true;
}

BOOST_PYTHON_MODULE(_validaddr)
{
    using namespace boost::python;
    def("validate_address", validate_address);
}

