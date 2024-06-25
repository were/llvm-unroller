#include <string>

#include "llvm/IR/Value.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"

namespace unroller {

inline std::string printType(llvm::Type *t) {
  std::string buffer;
  llvm::raw_string_ostream oss(buffer);
  oss << *t;
  return oss.str();
}

inline std::string namify(const std::string &s, bool with_percentage = true) {
  std::string ret;
  for (auto c : s) {
    if (!isdigit(c) && !isalpha(c)) {
      ret.push_back('_');
    } else {
      ret.push_back(c == '.' ? '_' : c);
    }
  }
  return (with_percentage ? "%" : "") + ret;
}

inline std::string namifyValue(llvm::Value *v, llvm::Module *m, bool with_type) {
  std::string ret;
  llvm::raw_string_ostream oss(ret);
  v->printAsOperand(oss, false, m);
  return (with_type ? printType(v->getType()) + " " : "") + namify(oss.str());
}

} // namespace unroller

