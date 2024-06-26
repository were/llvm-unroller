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

std::string dumpRightValue(llvm::Value *rval, llvm::Module *mod, bool with_type, LinearizedValues &cache) {
  std::string res;
  llvm::raw_string_ostream oss(res);
  if (llvm::isa<llvm::GlobalValue>(rval) ||
      llvm::isa<llvm::ConstantInt>(rval) ||
      llvm::isa<llvm::ConstantVector>(rval) ||
      llvm::isa<llvm::ConstantDataVector>(rval) ||
      llvm::isa<llvm::PoisonValue>(rval)) {
    oss << "\"";
    rval->printAsOperand(oss, with_type, mod);
    oss << "\"";
  } else {
    oss << cache[rval];
  }
  return res;
}

struct DumpInstruction {
  llvm::Instruction *ip;
  std::string dump;
  llvm::Instruction *raw;
  bool valued;

  DumpInstruction(llvm::Instruction *raw_)
    : ip(nullptr), dump(), raw(raw_), valued(false) {}

  DumpInstruction(llvm::Instruction *ip, std::string dump_)
    : ip(ip), dump(dump_), raw(nullptr), valued(false) {}

  llvm::Instruction *getInsertPoint() {
    if (ip) {
      return ip;
    }
    if (valued) {
      return raw->getNextNode();
    }
    return raw;
  }
};

DumpInstruction dumpInstruction(llvm::Value *v, LinearizedValues &cache) {
  if (auto i = llvm::dyn_cast<llvm::Instruction>(v)) {
    DumpInstruction res(i);
    auto &valued = res.valued;
    llvm::raw_string_ostream oss(res.dump);
    oss << "  {\n";
    oss << "    \"raw\": \"" << *v << "\",\n";
    auto mod = i->getParent()->getParent()->getParent();
    if (auto br = llvm::dyn_cast<llvm::BranchInst>(i)) {
      oss << "    \"opcode\": \"br\",\n";
      oss << "    \"from\": " << cache[br->getParent()] << "\n";
      valued = false;
    } else if (auto ai = llvm::dyn_cast<llvm::AllocaInst>(i)) {
      oss << "    \"lval\": " << cache[ai] << ",\n";
      oss << "    \"opcode\": \"alloca\",\n";
      oss << "    \"align\": " << ai->getAlign().value() << ",\n";
      oss << "    \"type\": \"" << *ai->getAllocatedType() << "\"\n";
      valued = false; // TODO(@were): I am not sure if this is correct.
    } else if (auto bo = llvm::dyn_cast<llvm::BinaryOperator>(i)) {
      oss << "    \"lval\": " << cache[bo] << ",\n";
      oss << "    \"opcode\": \"" << bo->getOpcodeName() << "\",\n";
      oss << "    \"type\": \"" << *bo->getType() << "\",\n";
      oss << "    \"lhs\": " << dumpRightValue(bo->getOperand(0), mod, false, cache) << ",\n";
      oss << "    \"rhs\": " << dumpRightValue(bo->getOperand(1), mod, false, cache) << ",\n";
      valued = true;
    } else if (auto icmp = llvm::dyn_cast<llvm::ICmpInst>(i)) {
      oss << "    \"lval\": " << cache[icmp] << ",\n";
      oss << "    \"pred\": \"" << llvm::CmpInst::getPredicateName(icmp->getPredicate()) << "\",\n";
      oss << "    \"type\": \"" << *icmp->getType() << "\",\n";
      oss << "    \"lhs\": " << dumpRightValue(icmp->getOperand(0), mod, false, cache) << ",\n";
      oss << "    \"rhs\": " << dumpRightValue(icmp->getOperand(1), mod, false, cache) << ",\n";
      valued = true;
    } else if (auto phi = llvm::dyn_cast<llvm::PHINode>(i)) {
      oss << "    \"lval\": " << cache[phi] << ",\n";
      oss << "    \"opcode\": \"phi\",\n";
      oss << "    \"type\": \"" << *phi->getType() << "\",\n";
      oss << "    \"incoming\": [\n";
      for (int i = 0; i < phi->getNumIncomingValues(); ++i) {
        oss << "      {\n";
        oss << "        \"from\": " << cache[phi->getIncomingBlock(i)] << ",\n";
        auto rval = dumpRightValue(phi->getIncomingValue(i), mod, false, cache);
        oss << "        \"value\": " << rval << "\n";
        oss << "      }";
        if (i + 1 < phi->getNumIncomingValues()) {
          oss << ",\n";
        } else {
          oss << "\n";
        }
      }
      oss << "    ],\n";
      valued = true;
    } else if (auto gep = llvm::dyn_cast<llvm::GetElementPtrInst>(i)) {
      oss << "    \"lval\": " << cache[gep] << ",\n";
      oss << "    \"opcode\": \"getelementptr\",\n";
      oss << "    \"type\": \"" << *gep->getSourceElementType() << "\",";
      oss << "    \"inbounds\": " << gep->isInBounds() << ",\n";
      oss << "    \"ptr\": " << dumpRightValue(gep->getPointerOperand(), mod, false, cache) << ",\n";
      oss << "    \"indices\": [ ";
      for (int i = 1; i < gep->getNumOperands(); ++i) {
        oss << dumpRightValue(gep->getOperand(i), mod, true, cache);
        if (i + 1 < gep->getNumOperands()) {
          oss << ",";
        }
      }
      oss << " ],\n";
      valued = true;
    } else if (auto load = llvm::dyn_cast<llvm::LoadInst>(i)) {
      oss << "    \"lval\": " << cache[load] << ",\n";
      oss << "    \"opcode\": \"load\",\n";
      oss << "    \"type\": \"" << *load->getType() << "\",\n";
      oss << "    \"ptr\": " << dumpRightValue(load->getPointerOperand(), mod, false, cache) << ",\n";
      oss << "    \"align\": " << load->getAlign().value() << ",\n";
      valued = true;
    } else if (auto select = llvm::dyn_cast<llvm::SelectInst>(i)) {
      oss << "    \"lval\": " << cache[select] << ",\n";
      oss << "    \"opcode\": \"select\",\n";
      oss << "    \"type\": \"" << *select->getType() << "\",\n";
      oss << "    \"cond\": " << dumpRightValue(select->getCondition(), mod, false, cache) << ",\n";
      oss << "    \"true_val\": " << dumpRightValue(select->getTrueValue(), mod, false, cache) << ",\n";
      oss << "    \"false_val\": " << dumpRightValue(select->getFalseValue(), mod, false, cache) << ",\n";
      valued = true;
    } else if (auto trunc = llvm::dyn_cast<llvm::TruncInst>(i)) {
      oss << "    \"lval\": " << cache[trunc] << ",\n";
      oss << "    \"opcode\": \"trunc\",\n";
      oss << "    \"dst_type\": \"" << *trunc->getType() << "\",\n";
      oss << "    \"src_type\": \"" << *trunc->getOperand(0)->getType() << "\",\n";
      oss << "    \"src\": " << dumpRightValue(trunc->getOperand(0), mod, false, cache) << ",\n";
      valued = true;
    } else if (auto zext = llvm::dyn_cast<llvm::ZExtInst>(i)) {
      oss << "    \"lval\": " << cache[zext] << ",\n";
      oss << "    \"opcode\": \"zext\",\n";
      oss << "    \"dst_type\": \"" << *zext->getType() << "\",\n";
      oss << "    \"src_type\": \"" << *zext->getOperand(0)->getType() << "\",\n";
      oss << "    \"src\": " << dumpRightValue(zext->getOperand(0), mod, false, cache) << ",\n";
      valued = true;
    } else if (auto store = llvm::dyn_cast<llvm::StoreInst>(i)) {
      oss << "    \"opcode\": \"store\",\n";
      oss << "    \"val\": " << dumpRightValue(store->getValueOperand(), mod, false, cache) << ",\n";
      oss << "    \"ptr\": " << dumpRightValue(store->getPointerOperand(), mod, false, cache) << ",\n";
      oss << "    \"align\": " << store->getAlign().value() << "\n";
      valued = false;
    } else if (auto call = llvm::dyn_cast<llvm::CallInst>(i)) {
      oss << "    \"opcode\": \"call\",\n";
      oss << "    \"tail\": \"" << call->isTailCall() << "\",\n";
      oss << "    \"type\": \"" << *call->getType() << "\",\n";
      if (!call->getType()->isVoidTy()) {
        oss << "    \"lval\": " << cache[call] << ",\n";
      }
      oss << "    \"callee\": \"";
      call->getCalledOperand()->printAsOperand(oss, false, mod);
      oss << "\",\n";
      oss << "    \"args\": [\n";
      for (int i = 0; i < call->getNumOperands() - 1; ++i) {
        auto arg = call->getOperand(i);
        oss << dumpRightValue(arg, mod, false, cache);
        if (i + 1 < call->getNumOperands() - 1) {
          oss << ",";
        }
      }
      oss << "]\n";
      if (call->getType()->isVoidTy()) {
        valued = false;
      } else {
        oss << ",";
        valued = true;
      }
    } else if (auto ret = llvm::dyn_cast<llvm::ReturnInst>(i)) {
      assert(false && "Return should not be handled here.");
    } else {
      oss << "  // TODO: Support dump for the inst above.\n";
    }
    if (!valued) {
      oss << "  },\n";
    }
    return res;
  }
  llvm::errs() << *v << "\n";
  assert(false && "Unsupported value type.");
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

void createValueDump(llvm::Instruction *raw, llvm::IRBuilder<> &builder, llvm::Module *m,
                     llvm::Function *printf) {
  llvm::Constant *fmt_payload = nullptr;
  llvm::Value *to_dump = raw;
  if (raw->getType()->isIntegerTy()) {
    auto ity = llvm::cast<llvm::IntegerType>(raw->getType());
    if (ity->getScalarSizeInBits() < 64) {
      to_dump = builder.CreateSExtOrBitCast(raw, builder.getInt64Ty());
    }
    fmt_payload = llvm::ConstantDataArray::getString(m->getContext(), "    \"value\": %ld  },\n");
  } else if (raw->getType()->isPointerTy()) {
    auto casted = builder.CreateBitOrPointerCast(raw, builder.getInt64Ty());
    fmt_payload = llvm::ConstantDataArray::getString(m->getContext(), "    \"value\": %ld  },\n");
    to_dump = casted;
  } else {
    assert(false && "Unsupported type.");
  }
  auto fmt_gv = new llvm::GlobalVariable(
    *m, fmt_payload->getType(), false, llvm::GlobalValue::PrivateLinkage, fmt_payload, ".str", 0,
    llvm::GlobalValue::NotThreadLocal, llvm::GlobalValue::ExternalLinkage);
  fmt_gv->setAlignment(llvm::MaybeAlign(1));
  fmt_gv->setUnnamedAddr(llvm::GlobalValue::UnnamedAddr::Global);
  auto call = builder.CreateCall(printf, { fmt_gv, to_dump });
  llvm::Attribute noundef =
     llvm::Attribute::get(builder.getContext(), llvm::Attribute::AttrKind::NoUndef);
  call->addParamAttr(0, noundef);
  call->addParamAttr(1, noundef);
}

void instrumentEachInstruction(
  std::ofstream &ofs,
  llvm::Module *m,
  const std::set<std::string> &entrances
) {
  llvm::IRBuilder<> builder(m->getContext());
  m->getOrInsertFunction("\01_fputs", llvm::FunctionType::get(
    llvm::Type::getInt32Ty(m->getContext()),
    {llvm::Type::getInt8PtrTy(m->getContext()), llvm::Type::getInt8PtrTy(m->getContext())},
    false));
  auto fputs = m->getFunction("\01_fputs");

  m->getOrInsertFunction("printf", llvm::FunctionType::get(
    llvm::Type::getInt32Ty(m->getContext()),
    {llvm::Type::getInt8PtrTy(m->getContext())},
    true));
  auto printf = m->getFunction("printf");

  // TODO(@were): Give this file descriptor a named file instead of stdout.
  auto *__stdout = m->getGlobalVariable("__stdoutp");
  if (!__stdout) {
    __stdout = new llvm::GlobalVariable(
      *m, llvm::PointerType::get(llvm::Type::getInt8Ty(m->getContext()), 0),
      true, llvm::GlobalValue::ExternalLinkage, nullptr, "__stdoutp", 0,
      llvm::GlobalValue::NotThreadLocal, llvm::GlobalValue::ExternalLinkage);
  }

  auto linearized = unroller::linearizeComputationalValues(*m);
  // TODO(@were): Reopen this later to declare intrinsics.
  // std::ostringstream intrinsics;
  // {
  //   for (auto &gv: m->globals()) {
  //     std::string s;
  //     llvm::raw_string_ostream oss(s);
  //     oss << gv;
  //     intrinsics << "/*\n" << s << "\n*/\n";
  //     for (size_t i = 0; i < s.size(); ++i) {
  //       intrinsics << "  ofs.put(" << (int)s[i] << ");\n";
  //     }
  //   }
  //   for (auto &f: m->functions()) {
  //     std::string s;
  //     llvm::raw_string_ostream oss(s);
  //     if (f.isDeclaration()) {
  //       oss << f;
  //       intrinsics << "/*\n" << s << "\n*/\n";
  //       for (size_t i = 0; i < s.size(); ++i) {
  //         intrinsics << "  ofs.put(" << (int)s[i] << ");\n";
  //       }
  //     }
  //   }
  // }

  for (auto &f: m->functions()) {
    if (f.isDeclaration()) {
      continue;
    }
    auto &workset = linearized[&f];
    std::vector<DumpInstruction> tracer;
    bool is_entrance = entrances.count(f.getName().str());
    if (is_entrance) {
      tracer.emplace_back(&f.getEntryBlock().front(), "{\n");
      tracer.emplace_back(&f.getEntryBlock().front(), "  \"function\": \"" + f.getName().str() + "\",\n");
      std::string args = "  \"args\": [";
      bool virgin = true;
      for (auto &arg: f.args()) {
        std::string buf;
        llvm::raw_string_ostream oss(buf);
        if (!virgin) {
          args += ", ";
        }
        args += "\"" + namifyValue(&arg, m, true) + "\"";
        virgin = false;
      }
      args += "],";
      tracer.emplace_back(&f.getEntryBlock().front(), args);
      tracer.emplace_back(&f.getEntryBlock().front(), "  \"trace\": [\n");
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
          auto dump = dumpInstruction(&cur, workset);
          if (&ip != &cur) {
            dump.ip = &ip;
          }
          tracer.push_back(dump);
        };
        if (!phis.empty()) {
          for (auto &phi : phis) {
            func(*phi, i);
          }
          phis.clear();
        }
        if (auto ret = llvm::dyn_cast<llvm::ReturnInst>(&i)) {
          if (is_entrance) {
            std::string trace_name = f.getName().str() + "_trace.ll";
            std::string ret_buffer;
            llvm::raw_string_ostream ret_oss(ret_buffer);
            ret_oss << "  {\n";
            if (ret->getReturnValue()) {
              ret_oss << "    \"opcode\": \"ret\",\n";
              ret_oss << "    \"value\": " << dumpRightValue(ret->getReturnValue(), m, false, workset) << ",\n";
              ret_oss << "    \"type\": \"" << *ret->getReturnValue()->getType() << "\"\n";
            } else {
              ret_oss << "    \"opcode\": \"ret\",\n";
              ret_oss << "    \"value\": \"void\"\n";
            }
            ret_oss << "  }\n";
            ret_oss << "  ]\n"; // End of trace.
            ret_oss << "}\n"; // End of function.
            tracer.push_back({&i, ret_oss.str()});
          } else {
            // TODO: Handle non-entrance returns.
          }
        } else {
          func(i, i);
        }
      }
    }
    // insert tracers
    for (auto &elem: tracer) {
      auto ip = elem.getInsertPoint();
      builder.SetInsertPoint(ip);
      createTraceDump(elem.dump, builder, m, fputs, __stdout);
      if (elem.valued) {
        assert(elem.raw);
        createValueDump(elem.raw, builder, m, printf);
      }
    }
  }
  std::string buf;
  llvm::raw_string_ostream oss(buf);
  oss << *m;
  ofs << oss.str();
}

}
