/* Copyright (c) 2017, Fengping Bao <jamol@live.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef __DnsResolver_h__
#define __DnsResolver_h__

#include "kmdefs.h"

#include <string>
#include <map>
#include <list>
#include <vector>
#include <unordered_map>
#include <memory>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>

#if defined(KUMA_OS_WIN)
# include <Ws2tcpip.h>
#else
# include <sys/socket.h>
#endif

KUMA_NS_BEGIN
using LockType = std::mutex;
using LockGuard = std::lock_guard<LockType>;
using LockTypeR = std::recursive_mutex;
using LockGuardR = std::lock_guard<LockTypeR>;

class DnsRecord;
class DnsResolver final {
public:
    class Slot;
    using Token = std::weak_ptr<Slot>;
    
    static DnsResolver& get();
    KMError getAddress(const std::string &host, sockaddr_storage &addr);
    KMError getAddresses(const std::string &host, std::vector<sockaddr_storage> &addr_list);
    // Resolve a host synchronously.
    KMError resolve(const std::string &host, sockaddr_storage &addr);
    // Resolve a host asynchronously.
    template<typename F> // F: void(KMError, sockaddr_storage&)
    Token resolve(const std::string &host, F &&f) {
        if (host.empty()) {
            return {};
        }
        auto slot = std::make_shared<Slot>(std::forward<F>(f));
        {
            LockGuard g(locker_);
            auto &slots = requests_[host];
            slots.emplace_back(slot);
        }
        conv_.notify_one();
        return slot;
    }
    void cancel(const std::string &host, const Token &t);
    void stop();

    class Slot
    {
        using Callback = std::function<void(KMError, sockaddr_storage&)>;
    public:
        template<typename F> // F: void(KMError, sockaddr_storage&)
        Slot(F &&f) : cb(std::forward<F>(f)) {}
        void cancel() {
            LockGuardR g(m);
            cb = {};
        }
        
    protected:
        friend class DnsResolver;
        void operator()(KMError err, sockaddr_storage &addr) {
            LockGuardR g(m);
            if (cb) {
                cb(err, addr);
            }
        }
        Callback cb;
        LockTypeR m;
    };
    
protected:
    DnsResolver();
    ~DnsResolver();
    
    bool init();
    void dnsProc();
    KMError doResolve(const std::string &host, sockaddr_storage &addr);
    
    void addRecord(const DnsRecord &dr);
    void addRecord(DnsRecord &&dr);
    
protected:
    LockType locker_;
    using SlotList = std::list<std::shared_ptr<Slot>>;
    std::unordered_map<std::string, SlotList> requests_;
    std::vector<std::thread> threads_;
    int thread_count_ = 1;
    bool stop_flag_ = false;
    std::condition_variable conv_;
};

KUMA_NS_END

#endif /* __DnsResolver_h__ */
