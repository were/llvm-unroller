#include <iostream>
#include <fstream>
#include <set>

#include "llvm/AsmParser/Parser.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/raw_ostream.h"

#include "unroller/instrumenter.h"

int main(int argc, char** argv) {

  llvm::SMDiagnostic Err;
  llvm::LLVMContext Ctx;

  auto mod = llvm::parseAssemblyFile(argv[1], Err, Ctx);
  auto cname = mod->getName() + ".instrumented.ll";
  std::set<std::string> entrances;
  for (int i = 2; i < argc; i++) {
    entrances.insert(argv[i]);
  }
  auto ofs = std::ofstream(cname.str());
  unroller::instrumentEachInstruction(ofs, mod.get(), entrances);

  return 0;
}
