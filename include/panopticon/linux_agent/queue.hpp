#pragma once

#include <algorithm>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <optional>

namespace panopticon::linux_agent {

enum class event_priority : std::uint8_t { low, normal, security };

struct queue_metrics {
    std::size_t depth{};
    std::uint64_t dropped{};
};

// Security events replace lower-priority queued work. Equal/lower-priority events are
// rejected when full; producers never block indefinitely on a telemetry burst.
template <typename item_type>
class bounded_priority_queue {
public:
    explicit bounded_priority_queue(const std::size_t capacity) : capacity_{capacity} {}

    [[nodiscard]] bool try_push(event_priority priority, item_type item) {
        std::lock_guard lock{mutex_};
        if (capacity_ == 0U) {
            ++dropped_;
            return false;
        }
        if (items_.size() == capacity_) {
            const auto candidate = std::find_if(items_.begin(), items_.end(), [priority](const entry& item) {
                return item.priority < priority;
            });
            if (candidate == items_.end()) {
                ++dropped_;
                return false;
            }
            items_.erase(candidate);
            ++dropped_;
        }
        items_.push_back(entry{priority, std::move(item)});
        available_.notify_one();
        return true;
    }

    [[nodiscard]] std::optional<item_type> try_pop() {
        std::lock_guard lock{mutex_};
        if (items_.empty()) {
            return std::nullopt;
        }
        const auto highest = std::max_element(items_.begin(), items_.end(), [](const entry& left, const entry& right) {
            return left.priority < right.priority;
        });
        item_type item{std::move(highest->item)};
        items_.erase(highest);
        return item;
    }

    [[nodiscard]] queue_metrics metrics() const {
        std::lock_guard lock{mutex_};
        return {items_.size(), dropped_};
    }

private:
    struct entry {
        event_priority priority;
        item_type item;
    };

    const std::size_t capacity_;
    mutable std::mutex mutex_;
    std::condition_variable available_;
    std::deque<entry> items_;
    std::uint64_t dropped_{};
};

}  // namespace panopticon::linux_agent
