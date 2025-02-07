#include "patcher.h"
#include <iostream>

Patcher::Patcher()
    : ks_(nullptr), initialized_(false) {}

Patcher::~Patcher() {
  if (initialized_)
    {
      ks_close(ks_);
    }
}

bool Patcher::init(ks_arch arch, ks_mode mode)
{
  ks_err err = ks_open(arch, mode, &ks_);
  if (err != KS_ERR_OK)
    {
      std::cerr << "Error opening Keystone: " << ks_strerror(err) << std::endl;
      return false;
    }
  initialized_ = true;

  return true;
}

std::vector<uint8_t> Patcher::assemble(const std::string &assembly,
                                       uint64_t address,
                                       bool &success)
{
  std::vector<uint8_t> result;
  success = false;

  if (!initialized_)
    {
      std::cerr << "Patcher not initialized" << std::endl;
      return result;
    }

  unsigned char *encode = nullptr;
  size_t size = 0;
  size_t count = 0;

  size_t aCount = ks_asm(ks_, assembly.c_str(), address, &encode, &size, &count);
  if (aCount == 0)
    {
      ks_err err = ks_errno(ks_);
      std::cerr << "Error assembling instruction: " << ks_strerror(err) << std::endl;

      if (encode)
        ks_free(encode);

      return result;
    }

  if (size > 0)
    {
      result.assign(encode, encode + size);
      success = true;
    }

  ks_free(encode);

  return result;
}
