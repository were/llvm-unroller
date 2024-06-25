#include <unordered_map>

#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"

namespace unroller {

using LinearizedValues = std::unordered_map<llvm::Value*, int>;
using LinearizedFuncs = std::unordered_map<llvm::Function*, LinearizedValues>;

/*!
 * \brief Linearize the identifiable values in the module, including args, blocks, and computational
 * instructions.
 */
LinearizedFuncs linearizeComputationalValues(llvm::Module& m);

}
