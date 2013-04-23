#include <future>
#include <mutex>
#include <unordered_set>

#include <boost/python.hpp>
namespace python = boost::python;

#include <bitcoin/bitcoin.hpp>

namespace fmon
{

using namespace bc;

using std::placeholders::_1;
using std::placeholders::_2;

class monitor
{
public:
    typedef protocol::completion_handler completion_handler;

    typedef std::function<
        void (const message::transaction&)> transaction_handler;

    monitor();

    std::error_code start(transaction_handler handle_tx);
    std::error_code stop();

    void set_latest_block(const hash_digest& hash);

private:
    typedef boost::circular_buffer<hash_digest> filter_buffer;

    void watch(channel_ptr node);
    void receive_inventory(const std::error_code& ec,
        const message::inventory& inv, channel_ptr node);
    void receive_transaction(const std::error_code& ec,
        const message::transaction& tx, channel_ptr node);
    void receive_block(const std::error_code& ec,
        const message::block& blk, channel_ptr node);

    // Check whether the hash exists in our filter.
    bool transaction_is_filtered(const hash_digest& tx_hash);

    async_service service_;
    hosts hosts_;
    handshake shake_;
    network network_;
    protocol protocol_;

    // Avoid downloading the same transaction multiple times by
    // temporarily filtering it.
    filter_buffer tx_filter_;
    transaction_handler handle_tx_;
};

monitor::monitor()
  : service_(1), hosts_(service_), shake_(service_), network_(service_),
    protocol_(service_, hosts_, shake_, network_), tx_filter_(40)
{
}

std::error_code monitor::start(transaction_handler handle_tx)
{
    handle_tx_ = handle_tx;
    std::promise<std::error_code> promise;
    auto future = promise.get_future();
    protocol_.start([&](const std::error_code& ec)
        {
            promise.set_value(ec);
        });
    protocol_.subscribe_channel(
        std::bind(&monitor::watch, this, _1));
    return future.get();
}
std::error_code monitor::stop()
{
    std::promise<std::error_code> promise;
    auto future = promise.get_future();
    protocol_.stop([&](const std::error_code& ec)
        {
            promise.set_value(ec);
        });
    std::error_code ec = future.get();
    if (ec)
        return ec;
    service_.stop();
    service_.join();
    return std::error_code();
}

void monitor::set_latest_block(const hash_digest& hash)
{
    static hash_digest latest_block = null_hash;
    if (latest_block == hash)
        return;
    latest_block = hash;
    message::get_data getdat;
    getdat.inventories.push_back({message::inventory_type::block, hash});
    protocol_.broadcast(getdat);
}

void monitor::watch(channel_ptr node)
{
    node->subscribe_inventory(
        std::bind(&monitor::receive_inventory, this, _1, _2, node));
    node->subscribe_transaction(
        std::bind(&monitor::receive_transaction, this, _1, _2, node));
    node->subscribe_block(
        std::bind(&monitor::receive_block, this, _1, _2, node));
    protocol_.subscribe_channel(
        std::bind(&monitor::watch, this, _1));
}

void monitor::receive_inventory(const std::error_code& ec,
    const message::inventory& inv, channel_ptr node)
{
    if (ec)
    {
        log_error() << "Error receiving inventory: " << ec.message();
        return;
    }
    message::get_data request_txs;
    for (const message::inventory_vector& ivec: inv.inventories)
    {
        // Only interested in txs
        if (ivec.type != message::inventory_type::transaction)
            continue;
        if (transaction_is_filtered(ivec.hash))
            continue;
        request_txs.inventories.push_back(ivec);
    }
    node->send(request_txs, [](const std::error_code& ec)
        {
            if (ec)
                log_error() << "Error requesting transactions from node.";
        });
    node->subscribe_inventory(
        std::bind(&monitor::receive_inventory, this, _1, _2, node));
}

void monitor::receive_transaction(const std::error_code& ec,
    const message::transaction& tx, channel_ptr node)
{
    if (ec)
    {
        log_error() << "Error receiving transaction: " << ec.message();
        return;
    }
    node->subscribe_transaction(
        std::bind(&monitor::receive_transaction, this, _1, _2, node));
    const hash_digest& tx_hash = hash_transaction(tx);
    if (transaction_is_filtered(tx_hash))
        return;
    tx_filter_.push_back(tx_hash);
    handle_tx_(tx);
}

void monitor::receive_block(const std::error_code& ec,
    const message::block& blk, channel_ptr node)
{
    // We can use a static value here since it's only used in this function.
    static filter_buffer blk_filter(10);
    auto block_is_filtered = [&blk_filter](const hash_digest& blk_hash)
        {
            return std::find(blk_filter.begin(), blk_filter.end(),
                blk_hash) != blk_filter.end();
        };
    const hash_digest& blk_hash = hash_block_header(blk);
    if (block_is_filtered(blk_hash))
        return;
    blk_filter.push_back(blk_hash);
    for (const message::transaction& tx: blk.transactions)
        handle_tx_(tx);
}

bool monitor::transaction_is_filtered(const hash_digest& tx_hash)
{
    return std::find(tx_filter_.begin(), tx_filter_.end(),
        tx_hash) != tx_filter_.end();
}

struct address_change
{
    std::string address;
    message::output_point outpoint;
};

class outputs_watch
{
public:
    typedef std::vector<address_change> address_change_list;

    void push(const std::string& address);
    address_change_list pull();

    void receive_transaction(const message::transaction& tx);

private:
    typedef std::unordered_set<std::string> address_set;

    // Locks are bad, but we provide a synchronous interface
    // to easily integrate with Python.
    std::mutex mutex_;
    address_set addresses_;
    address_change_list address_changes_;
};

void outputs_watch::push(const std::string& address)
{
    std::lock_guard<std::mutex> lock(mutex_);
    addresses_.insert(address);
}

outputs_watch::address_change_list outputs_watch::pull()
{
    std::lock_guard<std::mutex> lock(mutex_);
    address_change_list result = address_changes_;
    address_changes_.clear();
    return result;
}

void outputs_watch::receive_transaction(const message::transaction& tx)
{
    //log_info() << "Transaction: " << hash_transaction(tx);
    for (size_t i = 0; i < tx.outputs.size(); ++i)
    {
        const auto& output = tx.outputs[i];
        payment_address payaddr;
        if (!extract(payaddr, output.output_script))
            continue;
        std::lock_guard<std::mutex> lock(mutex_);
        if (addresses_.count(payaddr.encoded()) > 0)
        {
            // Add to the notification stack.
            address_change entry{
                payaddr.encoded(), {hash_transaction(tx), i}};
            address_changes_.push_back(entry);
        }
    }
}

class facade
{
public:
    bool start();
    bool stop();

    void push(const std::string& address);
    python::list pull();

    void set_latest_block(const std::string& hash);

private:
    // To make the facade copyable and compile with boost::python
    typedef std::shared_ptr<outputs_watch> outputs_watch_ptr;
    typedef std::shared_ptr<monitor> monitor_ptr;

    outputs_watch_ptr watch_;
    monitor_ptr monitor_;
};

bool facade::start()
{
    watch_ = std::make_shared<outputs_watch>();
    monitor_ = std::make_shared<monitor>();

    log_debug(log_domain::network).filter();
    log_debug(log_domain::protocol).filter();

    std::error_code ec = monitor_->start(std::bind(
        &outputs_watch::receive_transaction, watch_, _1));
    if (ec)
    {
        log_error() << "Error starting monitor: " << ec.message();
        return false;
    }
    return true;
}

bool facade::stop()
{
    std::error_code ec = monitor_->stop();
    if (ec)
    {
        log_error() << "Error stopping monitor: " << ec.message();
        return false;
    }
    return true;
}

void facade::push(const std::string& address)
{
    watch_->push(address);
}

python::list facade::pull()
{
    auto address_changes = watch_->pull();
    python::list result;
    for (const address_change& change: address_changes)
    {
        python::list entry;
        entry.append(change.address);
        const hash_digest& tx_hash = change.outpoint.hash;
        entry.append(std::string(tx_hash.begin(), tx_hash.end()));
        entry.append(change.outpoint.index);
        result.append(entry);
    }
    return result;
}

void facade::set_latest_block(const std::string& hash)
{
    hash_digest blk_hash;
    std::copy(hash.begin(), hash.end(), blk_hash.begin());
    monitor_->set_latest_block(blk_hash);
}

} // namespace fmon

BOOST_PYTHON_MODULE(fastmonitor)
{
    using namespace boost::python;
    using fmon::facade;
    class_<facade>("FastMonitor")
        .def("start", &facade::start)
        .def("stop", &facade::stop)
        .def("push", &facade::push)
        .def("pull", &facade::pull)
        .def("set_latest_block", &facade::set_latest_block)
    ;
}

