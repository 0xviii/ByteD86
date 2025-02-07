#include "disasm.h"
#include <iostream>

Disasm::Disasm()
    : handle_(0), initialized_(false) {}

Disasm::~Disasm()
{
  if (initialized_)
    {
      cs_close(&handle_);
    }
}

bool Disasm::init(cs_arch arch, cs_mode mode)
{
  cs_err err = cs_open(arch, mode, &handle_);
  if (err != CS_ERR_OK)
    {
      std::cerr << "Capstone error: " << cs_strerror(err) << std::endl;
      return false;
    }

  cs_option(handle_, CS_OPT_DETAIL, CS_OPT_ON);

  initialized_ = true;
  return true;
}

std::vector<InstructionInfo> Disasm::dBuff(const uint8_t* buffer, 
                                           size_t size, 
                                           uint64_t sAddr)
{
  std::vector<InstructionInfo> instructions;

  if (!initialized_)
    {
      std::cerr << "Disasm not initialized" << std::endl;
      return instructions;
    }

  cs_insn* insn;
  size_t count = cs_disasm(handle_, buffer, size, sAddr, 0, &insn);
  if (count > 0)
    {
      for (size_t i = 0; i < count; i++)
        {
          InstructionInfo info;
          info.address = insn[i].address;
          info.mnemonic = insn[i].mnemonic;
          info.op_str = insn[i].op_str;

          info.bytes.assign(insn[i].bytes, insn[i].bytes + insn[i].size);

          instructions.push_back(info);
        }
      cs_free(insn, count);
    }
  else
    {
      std::cerr << "No disassembled instructions" << std::endl;
    }

  return instructions;
}
