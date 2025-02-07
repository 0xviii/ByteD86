#ifndef PATCHER_H
#define PATCHER_H

#include <cstdint>
#include <vector>
#include <string>
#include <keystone/keystone.h>

class Patcher {
public:
    Patcher();
    ~Patcher();

    bool init(ks_arch arch, ks_mode mode);
    std::vector<uint8_t> assemble(const std::string& assembly, uint64_t address, bool& success);
private:
    ks_engine* ks_;
    bool initialized_;
};

#endif
