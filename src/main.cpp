#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <iomanip>

#include "disasm.h"
#include "patcher.h"

static void pInstruction(const std::vector<InstructionInfo>& instructions)
{
  for (auto& ins : instructions)
    {
      std::cout 
          << "0x" << std::hex << ins.address << ": "
          << std::setw(8) << std::left << ins.mnemonic 
          << " " << ins.op_str << std::endl;
    }
}

static bool pAddr(const std::string& str, uint64_t& addr)
{
  try
    {
      if (str.rfind("0x", 0) == 0)
        {
          addr = std::stoull(str, nullptr, 16);
        }
      else
        {
          addr = std::stoull(str);
        }
    }
  catch (...)
    {
      return false;
    }
  
  return true;
}

int main(int argc, char** argv)
{
  if (argc < 2)
    {
      std::cerr << "Use: " << argv[0] << " <file>" << std::endl;
      return 1;
    }

  std::string filename = argv[1];

  std::ifstream ifs(filename, std::ios::binary | std::ios::ate);
  if (!ifs)
    {
      std::cerr << "Erro ao abrir arquivo: " << filename << std::endl;
      return 1;
    }

  std::streamsize size = ifs.tellg();
  ifs.seekg(0, std::ios::beg);

  std::vector<uint8_t> buffer(size);
  if (!ifs.read(reinterpret_cast<char*>(buffer.data()), size))
    {
      std::cerr << "Error reading file" << std::endl;
      return 1;
    }

  Disasm dis;
  if (!dis.init(CS_ARCH_X86, CS_MODE_64))
    {
      return 1;
    }

  Patcher patcher;
  if (!patcher.init(KS_ARCH_X86, KS_MODE_64))
    {
      return 1;
    }


  uint64_t baseAddress = 0x1000;

  auto instructions = dis.dBuff(buffer.data(), buffer.size(), baseAddress);

  while (true)
    {
      std::cout << "> ";
      std::string line;

      if (!std::getline(std::cin, line))
        break;

      std::istringstream iss(line);
      std::string cmd;
      iss >> cmd;

      if (cmd == "exit" || cmd == "quit")
        {
          std::cout << "Exiting..." << std::endl;
          break;
        }
      else if (cmd == "dis")
        {
          instructions = dis.dBuff(buffer.data(), buffer.size(), baseAddress);
          pInstruction(instructions);
        }
      else if (cmd == "patch")
        {
          std::string addrStr, asmStr;
          iss >> addrStr;

          std::getline(iss, asmStr);

          if (!asmStr.empty() && asmStr[0] == ' ')
            {
              asmStr.erase(0, asmStr.find_first_not_of(' '));
            }

          if (addrStr.empty() || asmStr.empty())
            {
              std::cerr << "Use: patch <addr> \"<instruct>\"" << std::endl;
              continue;
            }

          uint64_t address = 0;
          if (!pAddr(addrStr, address))
            {
              std::cerr << "Invalid addr" << std::endl;
              continue;
            }

          bool success = false;
          auto patchBytes = patcher.assemble(asmStr, address, success);
          if (!success || patchBytes.empty())
            {
              std::cerr << "Failed to assemble instruction" << std::endl;
              continue;
            }

          if (address < baseAddress)
            {
              std::cerr << "Address smaller than base" << std::endl;
              continue;
            }
          uint64_t offset = address - baseAddress;
          if (offset + patchBytes.size() > buffer.size())
            {
              std::cerr << "Address smaller than baseAddress" << std::endl;
              continue;
            }

          for (size_t i = 0; i < patchBytes.size(); i++)
            {
              buffer[offset + i] = patchBytes[i];
            }

          std::cout << "Patch applied in 0x" << std::hex << address << ": " 
                    << asmStr << std::endl;
        }
      else if (cmd == "save")
        {
          std::string outFile;
          iss >> outFile;
          if (outFile.empty())
            {
              std::cerr << "Use: save <output_file>" << std::endl;
              continue;
            }

          std::ofstream ofs(outFile, std::ios::binary);
          if (!ofs)
            {
              std::cerr << "Error to open output file: " << outFile << std::endl;
              continue;
            }
          ofs.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
          ofs.close();
          std::cout << "File saved in: " << outFile << std::endl;
        }
      else
        {
          std::cout << "Cmds:\n"
                    << "  dis          - Disasm\n"
                    << "  patch <addr> \"<instr>\"  - apply patch\n"
                    << "  save <file>  - saves modified binary\n"
                    << "  exit\n";
        }
    }

  return 0;
}
