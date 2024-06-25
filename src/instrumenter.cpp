#include <cassert>
#include <cstdlib>
#include <optional>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <cctype>
#include <climits>
#include <iostream>

#include "llvm/IR/Argument.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/Format.h"
#include "llvm/Support/raw_ostream.h"

#include "unroller/instrumenter.h"

#include "./linearizer.h"
#include "./utils.h"

namespace unroller {

void dumpLeftValue(llvm::raw_ostream &oss, llvm::Value *lval, llvm::Module *mod, LinearizedValues &cache) {
  oss << "    auto lval = inc_identifier(scope.back().buffer, ";
  oss << cache[lval] << ", false);\n";
}

void dumpRightValue(llvm::raw_ostream &oss, llvm::Value *rval, llvm::Module *mod, bool with_type, LinearizedValues &cache) {
  if (llvm::isa<llvm::GlobalValue>(rval) ||
      llvm::isa<llvm::ConstantInt>(rval) ||
      llvm::isa<llvm::ConstantVector>(rval) ||
      llvm::isa<llvm::ConstantDataVector>(rval) ||
      llvm::isa<llvm::PoisonValue>(rval)) {
    oss << "\"";
    rval->printAsOperand(oss, with_type, mod);
    oss << "\"";
  } else {
    oss << "dump_value_entry(&scope.back().buffer[" << cache[rval] << "], " << with_type << ")";
  }
}

std::string dumpInstruction(llvm::Value *v, LinearizedValues &cache) {
  static int counter = 0;
  std::string buffer;
  llvm::raw_string_ostream oss(buffer);
  if (auto i = llvm::dyn_cast<llvm::Instruction>(v)) {
    oss << "  ofs << \"  ;" << *v << "\" << std::endl;\n";
    auto mod = i->getParent()->getParent()->getParent();
    if (auto br = llvm::dyn_cast<llvm::BranchInst>(i)) {
      if (br->getParent()->getName().empty()) {
        std::string temp;
        oss << "  ofs << \"  ; from: " << namifyValue(br->getParent(), mod, false) << "\" << std::endl;\n";
        oss << "  scope.back().from_block = " << cache[br->getParent()] << ";\n";
      }
    } else if (auto ai = llvm::dyn_cast<llvm::AllocaInst>(i)) {
      oss << "  {\n";
      dumpLeftValue(oss, ai, mod, cache);
      oss << "    ofs << \"  \" << lval << \" = alloca \" << ";
      oss << "\"" << *ai->getAllocatedType() << "\" << ";
      oss << "\", align " << ai->getAlign().value() << "\" << std::endl;\n";
      oss << "  }\n";
    } else if (auto bo = llvm::dyn_cast<llvm::BinaryOperator>(i)) {
      oss << "  {\n";
      dumpLeftValue(oss, bo, mod, cache);
      oss << "    ofs << \"  \" << lval << \" = \" << \"" << bo->getOpcodeName() << " \" << \"" << *bo->getType() << "\";\n";
      oss << "    auto lhs = "; dumpRightValue(oss, bo->getOperand(0), mod, false, cache); oss << ";\n";
      oss << "    ofs << lhs << \", \";\n";
      oss << "    auto rhs = ";
      dumpRightValue(oss, bo->getOperand(1), mod, false, cache);
      oss << ";\n";
      oss << "    ofs << rhs << std::endl;\n";
      oss << "  }\n";
    } else if (auto icmp = llvm::dyn_cast<llvm::ICmpInst>(i)) {
      oss << "  {\n";
      dumpLeftValue(oss, icmp, mod, cache);
      icmp->getPredicate();
      oss << "    ofs << \"  \" << lval << \" = \" << \"icmp ";
      oss << llvm::CmpInst::getPredicateName(icmp->getPredicate()) << " \" << \"" << *icmp->getOperand(0)->getType() << "\";\n";
      oss << "    auto lhs = "; dumpRightValue(oss, icmp->getOperand(0), mod, false, cache); oss << ";\n";
      oss << "    ofs << lhs << \", \";\n";
      oss << "    auto rhs = ";
      dumpRightValue(oss, icmp->getOperand(1), mod, false, cache);
      oss << ";\n";
      oss << "    ofs << rhs << std::endl;\n";
      oss << "  }\n";
    } else if (auto phi = llvm::dyn_cast<llvm::PHINode>(i)) {
      oss << "  {\n";
      oss << "    char *value = 0;\n";
      for (int i = 0; i < phi->getNumIncomingValues(); ++i) {
        oss << "    if (scope.back().from_block == " << cache[phi->getIncomingBlock(i)] << ") {\n";
        oss << "      value = ";
        dumpRightValue(oss, phi->getIncomingValue(i), mod, false, cache);
        oss << ";\n";
        oss << "    }\n";
      }
      oss << "    assert(value && \"Wrong from block!\");\n";
      oss << "    strcpy(scope.back()[" << cache[phi] << "].vid, value);\n";
      oss << "    ofs << \"  ; PHI is: \" << ";
      dumpRightValue(oss, phi, mod, true, cache);
      oss << " << std::endl;\n";
      oss << "  }\n";
    } else if (auto gep = llvm::dyn_cast<llvm::GetElementPtrInst>(i)) {
      oss << "  {\n";
      dumpLeftValue(oss, gep, mod, cache);
      oss << "    ofs << \"  \" << lval << \" = getelementptr \" << ";
      if (gep->isInBounds()) {
        oss << "\"inbounds \" << ";
      }
      oss << "\"" << *gep->getSourceElementType() << ", \";\n";
      oss << "    auto arr = ";
      dumpRightValue(oss, gep->getPointerOperand(), mod, true, cache);
      oss << ";\n";
      oss << "    ofs << arr << \", \";\n";
      for (int i = 1; i < gep->getNumOperands(); ++i) {
        oss << "    auto idx" << i << " = "; dumpRightValue(oss, gep->getOperand(i), mod, true, cache); oss << ";\n";
        oss << "    ofs << idx" << i;
        if (i + 1 < gep->getNumOperands()) {
          oss << " << \", \";\n";
        } else {
          oss << " << std::endl;\n";
        }
      }
      oss << "  }\n";
    } else if (auto load = llvm::dyn_cast<llvm::LoadInst>(i)) {
      oss << "  {\n";
      dumpLeftValue(oss, load, mod, cache);
      oss << "    ofs << \"  \" << lval << \" = load \" << ";
      oss << "\"" << *load->getType() << ", \" << ";
      dumpRightValue(oss, load->getPointerOperand(), mod, true, cache);
      oss << " << \", align " << load->getAlign().value() << "\" << std::endl;\n";
      oss << "  }\n";
    } else if (auto select = llvm::dyn_cast<llvm::SelectInst>(i)) {
      oss << "  {\n";
      dumpLeftValue(oss, select, mod, cache);
      oss << "    ofs << \"  \" << lval << \" = select \";\n";
      oss << "    auto cond = "; dumpRightValue(oss, select->getCondition(), mod, true, cache); oss << ";\n";
      oss << "    ofs << cond << \", \";\n";
      oss << "    auto true_val = "; dumpRightValue(oss, select->getTrueValue(), mod, true, cache); oss << ";\n";
      oss << "    ofs << true_val << \", \";\n";
      oss << "    auto false_val = "; dumpRightValue(oss, select->getFalseValue(), mod, true, cache); oss << ";\n";
      oss << "    ofs << false_val << std::endl;\n";
      oss << "  }\n";
    } else if (auto trunc = llvm::dyn_cast<llvm::TruncInst>(i)) {
      oss << "  {\n";
      dumpLeftValue(oss, trunc, mod, cache);
      oss << "    ofs << \"  \" << lval << \" = trunc \";\n";
      oss << "    auto src = "; dumpRightValue(oss, trunc->getOperand(0), mod, true, cache); oss << ";\n";
      oss << "    ofs << src << \" to \";\n";
      oss << "    ofs << \"" << *trunc->getType() << "\" << std::endl;\n";
      oss << "  }\n";
    } else if (auto zext = llvm::dyn_cast<llvm::ZExtInst>(i)) {
      oss << "  {\n";
      dumpLeftValue(oss, zext, mod, cache);
      oss << "    ofs << \"  \" << lval << \" = zext \";\n";
      oss << "    auto src = "; dumpRightValue(oss, zext->getOperand(0), mod, true, cache); oss << ";\n";
      oss << "    ofs << src << \" to \";\n";
      oss << "    ofs << \"" << *zext->getType() << "\" << std::endl;\n";
      oss << "  }\n";
    } else if (auto store = llvm::dyn_cast<llvm::StoreInst>(i)) {
      oss << "  {\n";
      oss << "    ofs << \"  store \";";
      oss << "    auto val = "; dumpRightValue(oss, store->getValueOperand(), mod, true, cache); oss << ";\n";
      oss << "    ofs << val << \", \";\n";
      oss << "    auto ptr = "; dumpRightValue(oss, store->getPointerOperand(), mod, true, cache); oss << ";\n";
      oss << "    ofs << ptr << \", align " << store->getAlign().value() << "\" << std::endl;\n";
      oss << "  }\n";
    } else if (auto call = llvm::dyn_cast<llvm::CallInst>(i)) {
      oss << "  {\n";
      auto tail = call->isTailCall() ? "tail " : "";
      if (call->getType()->isVoidTy()) {
        oss << "    ofs << \"  " << tail << "call \" << ";
      } else {
        dumpLeftValue(oss, call, mod, cache);
        oss << "    ofs << \"  \" << lval << \" = " << tail << " call \" << ";
      }
      oss << "\"" << *call->getType() << " \" << \"";
      call->getCalledOperand()->printAsOperand(oss, false, mod);
      oss << "\" << \"(\";\n";
      for (int i = 0; i < call->getNumOperands() - 1; ++i) {
        auto arg = call->getOperand(i);
        oss << "    auto arg" << i << " = ";
        dumpRightValue(oss, arg, mod, true, cache);
        oss << ";\n";
        oss << "    ofs << arg" << i;
        if (i + 1 < call->getNumOperands() - 1) {
          oss << " << \", \";\n";
        } else {
          oss << " << \")\" << std::endl;\n";
        }
      }
      oss << "  }\n";
    } else if (auto ret = llvm::dyn_cast<llvm::ReturnInst>(i)) {
      assert(false && "Return should not be handled here.");
    } else {
      oss << "  // TODO: Support dump for the inst above.\n";
    }
  }
  return oss.str();
}

void createTraceDump(const std::string &s, llvm::IRBuilder<> &builder, llvm::Module *m,
                     llvm::Function *fputs, llvm::GlobalVariable *__stdoutp) {
  auto payload = llvm::ConstantDataArray::getString(m->getContext(), s);
  auto gv = new llvm::GlobalVariable(
    *m, payload->getType(), false, llvm::GlobalValue::PrivateLinkage, payload, ".str", 0,
    llvm::GlobalValue::NotThreadLocal, llvm::GlobalValue::ExternalLinkage);
  gv->setAlignment(llvm::MaybeAlign(1));
  gv->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  auto __stdout = builder.CreateLoad(llvm::Type::getInt8PtrTy(m->getContext()), __stdoutp);
  auto call = builder.CreateCall(fputs, { gv, __stdout });
  llvm::Attribute noundef =
    llvm::Attribute::get(builder.getContext(), llvm::Attribute::AttrKind::NoUndef);
  call->addParamAttr(0, noundef);
}

void instrumentEachInstruction(
  std::ofstream &ofs,
  llvm::Module *m,
  const std::set<std::string> &entrances
) {
  llvm::IRBuilder<> builder(m->getContext());
  auto aaa = m->getOrInsertFunction("\01_fputs", llvm::FunctionType::get(
    llvm::Type::getInt32Ty(m->getContext()),
    {llvm::Type::getInt8PtrTy(m->getContext()), llvm::Type::getInt8PtrTy(m->getContext())},
    false));
  auto fputs = m->getFunction("\01_fputs");

  // TODO(@were): Give this file descriptor a named file instead of stdout.
  auto *__stdout = m->getGlobalVariable("__stdoutp");
  if (!__stdout) {
    __stdout = new llvm::GlobalVariable(
      *m, llvm::PointerType::get(llvm::Type::getInt8Ty(m->getContext()), 0),
      true, llvm::GlobalValue::ExternalLinkage, nullptr, "__stdoutp", 0,
      llvm::GlobalValue::NotThreadLocal, llvm::GlobalValue::ExternalLinkage);
  }

  auto linearized = unroller::linearizeComputationalValues(*m);
  std::string value_cache_initializer;
  {
    llvm::raw_string_ostream initializer_oss(value_cache_initializer);

    for (auto &f: m->functions()) {
      if (f.isDeclaration()) {
        continue;
      }
      assert(linearized.count(&f) && "Function not linearized.");
      auto &workset = linearized[&f];
      std::vector<std::string> res(workset.size(), "");
      std::vector<std::string> vid_inits;

      for (auto &elem: workset) {
        std::ostringstream vid;
        std::ostringstream id;
        if (auto phi = llvm::dyn_cast<llvm::PHINode>(elem.first)) {
          vid << "phi_" << (void*)phi;
          id << "char " << vid.str() << "[32];";
          vid_inits.push_back(id.str());
        } else {
          vid << "value_" << (void*)elem.first;
          id << "char " << vid.str() << "[] = " << "\"" << namifyValue(elem.first, m, false) << "\";";
          vid_inits.push_back(id.str());
        }
        llvm::raw_string_ostream oss(res[elem.second]);
        oss << "  ValueEntry(" << vid.str() << ", \"" << *elem.first->getType() << "\"), // ";
        elem.first->printAsOperand(oss, true, m);
        oss << "\n";
      }

      for (auto &vid: vid_inits) {
        initializer_oss << vid << "\n";
      }

      initializer_oss << "ValueEntry " << namify(f.getName().str(), false) << "_cache[] = {\n";
      for (auto &elem: res) {
        initializer_oss << elem;
      }
      initializer_oss << "};\n";
    }
  }

  std::ostringstream intrinsics;
  {
    for (auto &gv: m->globals()) {
      std::string s;
      llvm::raw_string_ostream oss(s);
      oss << gv;
      intrinsics << "/*\n" << s << "\n*/\n";
      for (size_t i = 0; i < s.size(); ++i) {
        intrinsics << "  ofs.put(" << (int)s[i] << ");\n";
      }
    }
    for (auto &f: m->functions()) {
      std::string s;
      llvm::raw_string_ostream oss(s);
      if (f.isDeclaration()) {
        oss << f;
        intrinsics << "/*\n" << s << "\n*/\n";
        for (size_t i = 0; i < s.size(); ++i) {
          intrinsics << "  ofs.put(" << (int)s[i] << ");\n";
        }
      }
    }
  }

  for (auto &f: m->functions()) {
    if (f.isDeclaration()) {
      continue;
    }
    auto &workset = linearized[&f];
    std::vector<std::tuple<llvm::Instruction*, std::string>> tracer;
    bool is_entrance = entrances.count(f.getName().str());
    std::string dumper_name = "dump_trace_" + f.getName().str();
    if (is_entrance) {
      std::string runtime =
"\
#include <vector>\n\
#include <iostream>\n\
#include <fstream>\n\
#include <cstdio>\n\
#include <unordered_map>\n\
#include <string>\n\
#include <cstring>\n\
#include <cassert>\n\
struct ValueEntry {\n\
  int cnt;\n\
  char *vid;\n\
  const char *type;\n\
\
  ValueEntry(char *v, const char *t) : cnt(0), vid(v), type(t) {}\n\
};\n\
char *dump_value_entry(ValueEntry *self, bool with_type) {\n\
  static char res_buffer[512];\n\
  if (!self->cnt) {\n\
    sprintf(res_buffer, \"%s %s\", with_type ? self->type : \"\", self->vid);\n\
  } else {\n\
    sprintf(res_buffer, \"%s %s.%d\", with_type ? self->type : \"\", self->vid, self->cnt);\n\
  }\n\
  return res_buffer;\n\
}\n\
struct TraceScope {\n\
  ValueEntry *buffer;\n\
  int from_block;\n\
\
  ValueEntry &operator[](int key) {\n\
    return buffer[key];\n\
  }\n\
\
  TraceScope() {}\n\
\
};\n\
char *inc_identifier(ValueEntry *cache, int handle, bool with_type) {\n\
  cache[handle].cnt++;\n\
  char *res = dump_value_entry(&cache[handle], with_type);\n\
  return res;\n\
}\n\
";
      tracer.push_back({&f.getEntryBlock().front(), runtime});
      tracer.push_back({&f.getEntryBlock().front(), value_cache_initializer});
      std::string func_name = "void " + dumper_name + "(std::ostream &ofs, std::vector<TraceScope> &scope) {\n";
      tracer.push_back({&f.getEntryBlock().front(), func_name});
      std::string func_sig = "define " + printType(f.getReturnType()) + " @" + f.getName().str() + "(";
      bool virgin = true;
      for (auto &arg: f.args()) {
        auto value = dumpInstruction(&arg, workset);
        std::string buf;
        llvm::raw_string_ostream oss(buf);
        if (!virgin) {
          func_sig += ", ";
        }
        func_sig += namifyValue(&arg, m, true);
        virgin = false;
      }
      func_sig += ") {";
      func_sig = "  ofs << \"" + func_sig + "\" << std::endl;\n";
      tracer.push_back({&f.getEntryBlock().front(), func_sig});
    }
    for (auto &bb: f) {
      std::vector<llvm::PHINode*> phis;
      for (auto &i: bb) {
        if (llvm::isa<llvm::PHINode>(i)) {
          phis.push_back(llvm::cast<llvm::PHINode>(&i));
          continue;
        }
        auto func = [&builder, &m, &tracer, &workset](llvm::Instruction &cur, llvm::Instruction &ip) {
          std::ostringstream id;
          auto value = dumpInstruction(&cur, workset);
          tracer.push_back({&ip, value});
        };
        if (!phis.empty()) {
          for (auto &phi : phis) {
            func(*phi, i);
          }
          phis.clear();
        }
        if (auto ret = llvm::dyn_cast<llvm::ReturnInst>(&i)) {
          if (is_entrance) {
            std::string scope_init;
            for (auto &arg: f.args()) {
              std::string vid = namifyValue(&arg, m, false);
              std::string buf1;
              llvm::raw_string_ostream type(buf1);
              type << *arg.getType();
              scope_init += "  scope.back()[" + std::to_string(workset[&arg]) + "].vid = \"" + vid + "\";\n";
            }
            std::string trace_name = f.getName().str() + "_trace.ll";
            std::string host_main =
"int main() {\n\
  std::vector<TraceScope> scope;\n\
  std::ofstream ofs(\"" + trace_name + "\");\n\
  scope.emplace_back();\n\
  scope.back().buffer = " + namify(f.getName().str(), false) + "_cache;\n" +
  scope_init +
  intrinsics.str() +
  "\
  " + dumper_name + "(ofs, scope);\n\
  return 0;\n\
}\n";
            if (ret->getReturnValue()) {
              std::string ret_string;
              llvm::raw_string_ostream oss(ret_string);
              oss << "  ofs <<  \"  ret \" << ";
              dumpRightValue(oss, ret->getReturnValue(), m, true, workset);
              oss << " << std::endl;\n";
              tracer.push_back({&i, oss.str()});
            } else {
              tracer.push_back({&i, "  ofs << \"  ret void\" << std::endl;\n"});
            }

            tracer.push_back({&i, "  // leave the entrnace function\n  ofs << \"}\" << std::endl;\n}\n"});
            tracer.push_back({&i, host_main});
          } else {
            tracer.push_back({&i, "  // TODO: handled valued return\n"});
            tracer.push_back({&i, "  scope.pop();\n"});
          }
        } else {
          func(i, i);
        }
      }
    }
    // insert tracers
    for (auto &[i, value]: tracer) {
      builder.SetInsertPoint(i);
      createTraceDump(value, builder, m, fputs, __stdout);
    }
  }
  std::string buf;
  llvm::raw_string_ostream oss(buf);
  oss << *m;
  ofs << oss.str();
}

}
