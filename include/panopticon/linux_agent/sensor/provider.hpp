#pragma once

#include "panopticon/linux_agent/error.hpp"
#include "panopticon/linux_agent/sensor/records.hpp"

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace panopticon::linux_agent::sensor {

struct provider_health {
    std::string name;
    std::string state;  // active, degraded, unavailable, stopped
    std::string reason;
    std::vector<std::string> capabilities;
    std::uint64_t events{};
    std::uint64_t drops{};
    std::string family{};  // empty: the provider has no alternative
    std::string tier{};    // primary, or fallback when an earlier member of the family is preferred
};

// FIFO, bounded, multi-producer/single-consumer. Order matters for the entity graph (fork before
// exec before exit), so unlike bounded_priority_queue this never reorders; when full the new
// record is dropped and counted, and the consumer turns the count into a `loss` record and an
// immediate reconcile.
class record_queue {
public:
    explicit record_queue(const std::size_t capacity) : capacity_{capacity} {}

    bool push(raw_record record) {
        bool notify = false;
        {
            std::lock_guard lock{mutex_};
            if (items_.size() >= capacity_) {
                ++dropped_;
                return false;
            }
            items_.push_back(std::move(record));
            notify = items_.size() >= wake_threshold_;
        }
        // Waking the consumer per record costs two context switches per event; it is woken only
        // when the batch it is waiting for is complete.
        if (notify) available_.notify_one();
        return true;
    }

    // Moves up to `maximum` records into `out`. Waits up to `timeout` for the first record, then
    // up to `linger` for the batch to fill, trading a bounded latency for far fewer wake-ups.
    std::size_t pop_batch(std::vector<raw_record>& out, const std::size_t maximum, const std::chrono::milliseconds timeout,
                          const std::chrono::milliseconds linger = std::chrono::milliseconds{0}) {
        std::unique_lock lock{mutex_};
        if (items_.empty()) {
            wake_threshold_ = 1U;
            available_.wait_for(lock, timeout, [this] { return !items_.empty() || woken_; });
        }
        if (!items_.empty() && items_.size() < maximum && linger.count() > 0 && !woken_) {
            wake_threshold_ = maximum;
            available_.wait_for(lock, linger, [this, maximum] { return items_.size() >= maximum || woken_; });
        }
        wake_threshold_ = static_cast<std::size_t>(-1);
        woken_ = false;
        std::size_t moved = 0U;
        while (!items_.empty() && moved < maximum) {
            out.push_back(std::move(items_.front()));
            items_.pop_front();
            ++moved;
        }
        return moved;
    }

    void wake() {
        {
            std::lock_guard lock{mutex_};
            woken_ = true;
        }
        available_.notify_all();
    }

    [[nodiscard]] std::uint64_t take_dropped() {
        std::lock_guard lock{mutex_};
        const auto value = dropped_;
        dropped_ = 0U;
        return value;
    }

    [[nodiscard]] std::size_t depth() const {
        std::lock_guard lock{mutex_};
        return items_.size();
    }

private:
    const std::size_t capacity_;
    mutable std::mutex mutex_;
    std::condition_variable available_;
    std::deque<raw_record> items_;
    std::uint64_t dropped_{};
    std::size_t wake_threshold_{static_cast<std::size_t>(-1)};
    bool woken_{false};
};

// A telemetry source (ADR 005). Providers own their threads and only communicate through the
// record queue; they never touch the entity graph or the WAL.
class provider {
public:
    virtual ~provider() = default;
    [[nodiscard]] virtual std::string_view name() const noexcept = 0;
    // Providers of the same non-empty family are alternatives for one capability set, listed in
    // preference order: the pipeline runs the first that starts and keeps the rest on standby
    // (e.g. ebpf_process supersedes netlink_proc). Empty means an independent provider.
    [[nodiscard]] virtual std::string_view family() const noexcept { return {}; }
    [[nodiscard]] virtual std::vector<std::string> capabilities() const = 0;
    // Empty when the provider can run here, otherwise the reason it cannot.
    [[nodiscard]] virtual std::string probe() = 0;
    [[nodiscard]] virtual result<bool> start(record_queue& queue) = 0;
    // Asks the provider to begin stopping without waiting, so that providers that wake on a timer finish together.
    virtual void request_stop() noexcept {}
    virtual void stop() = 0;
    [[nodiscard]] virtual provider_health health() const = 0;
    // Records the kernel or the provider lost since the last call (e.g. netlink ENOBUFS); a
    // non-zero value means the entity graph must reconcile.
    [[nodiscard]] virtual std::uint64_t take_losses() = 0;
    // True when take_losses() counts lost events. Otherwise it counts overflows of a kernel buffer, each of
    // which lost an unknown number of events, and the loss record says so.
    [[nodiscard]] virtual bool losses_are_event_counts() const noexcept { return false; }
    // Events the provider deliberately dropped to stay within its rate budget since the last
    // call; the count is exact, so no reconcile is needed (reported as a `governor` loss).
    [[nodiscard]] virtual std::uint64_t take_governed() { return 0U; }
    // Inputs the provider read and refused to turn into events since the last call (an authentication
    // log line over the size limit, for example). Nothing about them reaches the stream, so without
    // this they would be invisible; the count is exact (reported as a `refused` loss).
    [[nodiscard]] virtual std::uint64_t take_refused() { return 0U; }
};

}  // namespace panopticon::linux_agent::sensor
