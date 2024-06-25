#include <fstream>

#include "llvm/IR/Module.h"

namespace unroller {

void instrumentEachInstruction(
  std::ofstream &ofs,
  llvm::Module *M,
  const std::set<std::string> &entrances);

}
