#ifndef DISASM_H
#define DISASM_H

#include <cstdint>
#include <vector>
#include <string>
#include <capstone/capstone.h>

struct InstructionInfo {
    uint64_t address;
    std::vector<uint8_t> bytes;
    std::string mnemonic;
    std::string op_str;
};

class Disasm {
public:
    Disasm();
    ~Disasm();

    bool init(cs_arch arch, cs_mode mode);
    std::vector<InstructionInfo> dBuff(const uint8_t* buffer, size_t size, uint64_t startAddress);

private:
    csh handle_;
    bool initialized_;
};

#endif
