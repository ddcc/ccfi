#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/PassManager.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#define DEBUG_TYPE "randstack"

using namespace llvm;

namespace {
  struct Randstack : public FunctionPass {
    static char ID;
    Randstack() : FunctionPass(ID) {
      initializeRandstackPass(*PassRegistry::getPassRegistry());
    }

    virtual bool runOnFunction(Function &F) {
	if (getenv("CCFI_DISABLE_RANDSTACK"))
	  return false;

	Module *M = F.getParent();
	LLVMContext &ctx = M->getContext();

	IRBuilder<> B(&F.getEntryBlock().front());

        Function *rdtsc = Intrinsic::getDeclaration(M,
                                Intrinsic::readcyclecounter);

	Value *tsc = B.CreateCall(rdtsc);
	Value *r = B.CreateAnd(tsc, B.getInt64(0xF));
	r = B.CreateShl(r, B.getInt64(4));

	Value *hack = B.CreateAlloca(Type::getInt8Ty(ctx), r);

	Function *prefetch = Intrinsic::getDeclaration(M,
				Intrinsic::prefetch);

	B.CreateCall4(prefetch, hack, B.getInt32(0), B.getInt32(0), B.getInt32(1));

	return true;
    }
  };
}

char Randstack::ID = 0;
INITIALIZE_PASS(Randstack, "randstack", "randomize stack", false, false)

FunctionPass *llvm::createRandstackPass() {
    return new Randstack();
}
