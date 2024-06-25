#include <unordered_map>

#include "llvm/IR/Function.h"
#include "llvm/IR/Value.h"

#include "./linearizer.h"
#include "./utils.h"

namespace unroller {

LinearizedFuncs linearizeComputationalValues(llvm::Module &m) {

  LinearizedFuncs res;

  for (auto &f : m) {
    res[&f] = LinearizedValues();
    auto &workmap = res[&f];
    for (auto &arg : f.args()) {
      auto ptr = llvm::cast<llvm::Value>(&arg);
      workmap[ptr] = workmap.size();
    }
    for (auto &bb : f) {
      workmap[&bb] = workmap.size();
      for (auto &i : bb) {
        workmap[&i] = workmap.size();
      }
    }
  }

  return res;
}

}
