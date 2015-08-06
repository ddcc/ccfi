/*
 * CCFI Function Pointer Protection
 */

#define DEBUG_TYPE "ccfi"

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
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/PassManager.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"

#include "CCFI.h"

// #define DEBUG_CHECKPTR 1

using namespace llvm;

// Utility Functions

bool isFuncPtr(Type *ty)
{
    if (!ty)
        return false;
    return ty->isPointerTy() && ty->getPointerElementType()->isFunctionTy();
}

uint32_t hashFuncType(Type *ty)
{
    uint32_t hash = 0;
    FunctionType *ft;

    if (!ty)
	return 0;

    //errs() << ty->isPointerTy() << "\n";
    //errs() << ty->getPointerElementType()->isFunctionTy() << "\n";
    ft = dyn_cast<FunctionType>(ty->getPointerElementType());
    if (!ft)
	return 0;

    for (Type::subtype_iterator SI = ft->param_begin(), SE = ft->param_end();
	    SI != SE; ++SI) {
	hash += (uint32_t)(*SI)->getTypeID();
	hash += hash << 10;
	hash += hash >> 6;
    }
    hash += hash << 3;
    hash ^= hash >> 11;
    hash += hash << 15;

    //errs() << "FUNC HASH " << hash << "\n";

    return hash;
}

// Module

CCFI::CCFI() : ModulePass(ID), gcb(NULL), enableTypedPtr(false)
{
    if (getenv("CCFI_ENABLE_TYPEDPTR") != NULL) {
	enableTypedPtr = true;
	errs() << "CCFI TYPEDPTR\n";
    }
}

bool CCFI::runOnModule(Module &M)
{
    bool mod = false;

    errs() << "CCFI pointer protection enabled\n";

    gcb = NULL;

    for (Module::global_iterator GI = M.global_begin(), GE = M.global_end();
            GI != GE; ++GI) {
	if (!GI->isExternallyInitialized()) {
	    Value &v = *GI;
	    mod |= doGlobal(M, v);
	}
    }

    for (Module::iterator MI = M.begin(), ME = M.end(); MI != ME; ++MI) {
        Function &F = *MI;
        for (Function::iterator FI = F.begin(), FE = F.end(); FI != FE; ++FI) {
            BasicBlock &BB = *FI;

            mod |= doBasicBlock(M, BB);
        }
    }

    finishGCB();

    return mod;
}

// Globals

bool CCFI::doGlobal(Module &M, Value &v, IRBuilder<> *B)
{
    PointerType *pt = dyn_cast<PointerType>(v.getType());
    assert(pt);

    Type *t = pt->getElementType();

    depth_t depth;

    return doGlobal(M, v, t, depth, B);
}

bool CCFI::doGlobal(Module &M, Value &v, Type *t, depth_t &depth, IRBuilder<> *B)
{
    bool mod = false;

    if (isFuncPtr(t) || isMemFptr(t)) {
        addGlobalMAC(M, v, t, depth, B);
        return true;
    }

    CompositeType *ct = dyn_cast<CompositeType>(t);
    if (!ct)
        return false;

    ArrayType *at = dyn_cast<ArrayType>(t);
    if (at) {
        Type *et = at->getElementType();

        for (uint64_t i = 0; i < at->getNumElements(); i++) {
            depth.push_back(i);
            mod |= doGlobal(M, v, et, depth, B);
            depth.pop_back();
        }
    }

    StructType *st = dyn_cast<StructType>(t);
    if (st) {
	if (v.getName().equals("llvm.global_ctors"))
		return mod;

	if (v.getName().equals("llvm.global_dtors"))
		return mod;

        for (uint64_t i = 0; i < st->getNumElements(); i++) {
            Type *et = st->getElementType(i);
            depth.push_back(i);
            mod |= doGlobal(M, v, et, depth, B);
            depth.pop_back();
        }
    }

    return mod;
}

void CCFI::doGlobalCall(LoadInst *LI)
{
    Module *m = LI->getParent()->getParent()->getParent();
    LLVMContext &ctx = m->getContext();

    Value *p = LI->getPointerOperand();
    GlobalVariable *g = dyn_cast<GlobalVariable>(p);

    IRBuilder<> B(LI);

    Constant *addmac = m->getOrInsertFunction("__ccfi_addmac_global",
                                              Type::getVoidTy(ctx),
                                              g->getType(),
                                              NULL);

    B.CreateCall(addmac, g);
}

void CCFI::addGlobalMAC(Module &M, Value &v, Type *t, depth_t &depth,
                         IRBuilder<> *b)
{
    LLVMContext &ctx = M.getContext();

    if (!b)
        b = getGCB(M);

    Value *val = &v;

    for (depth_t::iterator i = depth.begin(); i != depth.end(); ++i) {
        int idx = *i;

        val = b->CreateConstGEP2_32(val, 0, idx);
    }

    Constant *addmac = M.getOrInsertFunction("__ccfi_addmac_global",
                                             Type::getVoidTy(ctx),
                                             val->getType(),
                                             NULL);

    b->CreateCall(addmac, val);
}

IRBuilder<> *CCFI::getGCB(Module &M)
{
    if (gcb)
        return gcb;

    LLVMContext& ctx = M.getContext();

    Constant *C = M.getOrInsertFunction("_CCFI_global_ctor",
            Type::getVoidTy(ctx),
            NULL);

    Function* F = cast<Function>(C);
    F->setLinkage(GlobalValue::PrivateLinkage);
    appendToGlobalCtors(M, F, 1);

    BasicBlock *BB = BasicBlock::Create(ctx, "entry", F);
    gcb = new IRBuilder<>(BB);

    return gcb;
}

void CCFI::finishGCB()
{
    if (gcb) {
        gcb->CreateRetVoid();
        delete gcb;
        gcb = NULL;
    }
}

// Basic Block Routines

bool CCFI::doBasicBlock(Module &M, BasicBlock &BB)
{
    bool mod = false;

    SmallVector<CheckPoint, 64> failPoints;

    for (BasicBlock::iterator BI = BB.begin(), BE= BB.end(); BI != BE;) {
        Instruction *Inst = BI++;

        CallInst *CI = dyn_cast<CallInst>(Inst);
        if (CI)
            mod |= doCall(M, CI);

        ExtractValueInst *EV = dyn_cast<ExtractValueInst>(Inst);
        if (EV) {
            CheckPoint cp = doExtractValue(M, EV);
            if (cp.inst != NULL) {
                failPoints.push_back(cp);
                mod = true;
            }
        }

        StoreInst *SI = dyn_cast<StoreInst>(Inst);
        if (SI)
            mod |= doStore(M, SI);

        LoadInst *LI = dyn_cast<LoadInst>(Inst);
        if (LI) {
            Value *v = LI->getPointerOperand();
            PointerType *t = dyn_cast<PointerType>(v->getType());

            if (strncmp(v->getName().data(), "vfn", 3) == 0)
                continue;

            if (strncmp(v->getName().data(), "vtable", 6) == 0)
                continue;

            if (strncmp(LI->getName().data(), "memptr.virtualfn", 16) == 0)
                continue;

            if (strncmp(LI->getName().data(), "vtable", 6) == 0) {
                failPoints.push_back(doLoad(M, LI));
                mod = true;
                continue;
            }

            if (strncmp(LI->getName().data(), "memptr.vtable", 13) == 0) {
                failPoints.push_back(doLoad(M, LI));
                mod = true;
                continue;
            }

            if (isFuncPtr(t->getElementType())) {
                failPoints.push_back(doLoad(M, LI));
                mod = true;
            }
        }
    }

    LLVMContext &ctx = M.getContext();
    for (size_t i = 0, n = failPoints.size(); i != n; i++) {
	// Call __ccfi_failure on mismatch
	CheckPoint cp = failPoints[i];

	IRBuilder<> NPB(cp.insertionPt);
	Value *zeroValue = NPB.getInt64(0);
	Value *NPValue = NPB.CreateICmpNE(cp.func, zeroValue);
	Instruction *NPCheck = cast<Instruction>(NPValue);
	TerminatorInst *isNotNull = SplitBlockAndInsertIfThen(NPCheck, false);
	IRBuilder<> B(isNotNull);

	Value *checkptr = Intrinsic::getDeclaration(&M, Intrinsic::checkptr);
	Value *isNotValid;

#ifdef DEBUG_CHECKPTR
	checkptr = M.getOrInsertFunction("__ccfi_debug_checkptr",
						      Type::getInt64Ty(ctx),
						      Type::getInt64Ty(ctx),
						      Type::getInt64Ty(ctx),
						      NULL);
#endif

	Value *tmpFuncType = cp.func;
	if (enableTypedPtr) {
	    Value *funcHash = B.getInt64(cp.hash);
	    tmpFuncType = B.CreateXor(cp.func, funcHash);
	}

	if (cp.isMethodPtr) {
	    Value *oneValue = B.getInt64(1);
	    Value *maskVPtr = B.CreateAnd(cp.func, oneValue);
	    Value *isNotVPtr = B.CreateICmpNE(maskVPtr, oneValue);

	    Instruction *inst = cast<Instruction>(isNotVPtr);
	    TerminatorInst *isMethod = SplitBlockAndInsertIfThen(inst, false);
	    IRBuilder<> MB(isMethod);

	    Value *checkptr_isValid = MB.CreateCall2(checkptr, tmpFuncType, cp.addr);
	    isNotValid = MB.CreateICmpEQ(checkptr_isValid, zeroValue);
	} else {
	    Value *checkptr_isValid = B.CreateCall2(checkptr, tmpFuncType, cp.addr);
	    isNotValid = B.CreateICmpEQ(checkptr_isValid, zeroValue);
	}

	Instruction *validInst = cast<Instruction>(isNotValid);
	TerminatorInst *failTerminator = SplitBlockAndInsertIfThen(validInst, true);
	IRBuilder<> FB(failTerminator);
	Constant *CCFIFail = M.getOrInsertFunction("__ccfi_failure",
						      Type::getVoidTy(ctx),
						      Type::getInt64Ty(ctx),
						      Type::getInt64Ty(ctx),
						      NULL);
	FB.CreateCall2(CCFIFail, cp.func, cp.addr);
    }

    return mod;
}

// Handle Calls

bool CCFI::doCall(Module &M, CallInst *CI)
{
    Function *f = CI->getCalledFunction();

    if (!f)
        return false;

    if (!f->getName().equals("llvm.memcpy.p0i8.p0i8.i64"))
        return false;

    Value *dst = CI->getArgOperand(0);

    Value *v = NULL;
    Type *t = NULL;

    BitCastInst *bi = dyn_cast<BitCastInst>(dst);

    if (bi) {
        v = bi->getOperand(0);
        t = bi->getSrcTy();
    } else {
        ConstantExpr *ce = dyn_cast<ConstantExpr>(dst);

        if (!ce)
            return false;

        if (ce->getOpcode() != Instruction::BitCast)
            return false;

        v = ce->getOperand(0);
        t = v->getType();
    }

    if (!v)
        return false;

    PointerType *pt = dyn_cast<PointerType>(t);
    assert(pt);

    t = pt->getElementType();

    depth_t depth;

    Instruction *ni = CI->getNextNode();

    IRBuilder<> B(ni);

    return doGlobal(M, *v, &B);
}

// Handle Extract Value

CCFI::CheckPoint CCFI::doExtractValue(Module &M, ExtractValueInst *EV)
{
    CheckPoint cp;
    LLVMContext& ctx = M.getContext();

    if (strncmp(EV->getName().data(), "memptr.ptr", 10) != 0)
    {
	cp.inst = cp.insertionPt = NULL;
	cp.func = cp.addr = NULL;
	return cp;
    }

    Value *v = EV->getAggregateOperand();

    LoadInst *LI = dyn_cast<LoadInst>(v);
    assert(LI);

    Value *addr = LI->getPointerOperand();
    Value *func = EV;

    Instruction *ni = EV->getNextNode();
    IRBuilder<> B(ni);

    Value *tmpFunc = B.CreatePtrToInt(func, Type::getInt64Ty(ctx));
    Value *tmpAddr = B.CreatePtrToInt(addr, Type::getInt64Ty(ctx));

    cp.inst = EV;
    cp.insertionPt = ni;
    if (enableTypedPtr) {
	cp.hash = hashFuncType(func->getType());
    } else {
	cp.hash = 0;
    }
    cp.func = tmpFunc;
    cp.addr = tmpAddr;
    cp.isMethodPtr = true;

    return cp;
/*
    Value *oneValue = B.getInt64(1);
    Value *maskVPtr = B.CreateAnd(tmpFunc, oneValue);
    Value *isNotVPtr = B.CreateICmpNE(maskVPtr, oneValue);

    Value *checkptr = Intrinsic::getDeclaration(&M, Intrinsic::checkptr);
    Value *checkptr_isValid = B.CreateCall2(checkptr, tmpFunc, tmpAddr);

    Value *zeroValue = B.getInt64(0);
    Value *isNotValid = B.CreateICmpEQ(checkptr_isValid, zeroValue);

    Value *isNotOkay = B.CreateAnd(isNotVPtr, isNotValid);

    return cast<Instruction>(isNotOkay);*/
}

// Handle Stores

bool CCFI::doStore(Module &M, StoreInst *SI)
{
    Value *v = SI->getValueOperand();

    PointerType *t = dyn_cast<PointerType>(v->getType());

    if (t && t->getElementType()->isFunctionTy()) {
        doStoreCall(M, SI);
        return true;
    }

    if (checkVTableStore(M, SI))
        return true;

    if (checkMemberFPtrStore(M, SI))
        return true;

    if (checkVTTStore(M, SI))
	return true;

    return false;
}

bool CCFI::checkVTTStore(Module &M, StoreInst *SI)
{
    Value *v = SI->getValueOperand();

    LoadInst *li = dyn_cast<LoadInst>(v);

    if (!li)
            return false;

    if (li->getPointerOperand()->getName().find("vtt") == StringRef::npos)
            return false;

//  errs() << "Doing vtt\n";

    doStoreCall(M, SI);
    return true;
}

bool CCFI::isMemFptr(Type *t)
{
    StructType *st = dyn_cast<StructType>(t);

    if (!st || st->getNumElements() != 2)
            return false;

    for (int i = 0; i < 2; i++) {
            IntegerType *it = dyn_cast<IntegerType>(st->getElementType(i));

            if (!it || it->getBitWidth() != 64)
                    return false;
    }

    return true;
}

bool CCFI::checkMemberFPtrStore(Module &M, StoreInst *SI)
{
    Value *v = SI->getValueOperand();

    if (!isMemFptr(v->getType())) {
	    ConstantStruct *s = dyn_cast<ConstantStruct>(v);
	    if (!s)
		return false;

	    ConstantExpr *ce = NULL;
	    for (User::op_iterator I = s->op_begin(), IE = s->op_end();
			I != IE; ++I) {
		Value *x = *I;

		ce = dyn_cast<ConstantExpr>(x);
		break;
	    }
	    if (!ce)
		return false;

	    if (ce->getOpcode() != Instruction::PtrToInt)
		return false;

	    Value *x = *(ce->op_begin());

	    if (x->getValueID() != Value::FunctionVal)
		return false;
    }

    IRBuilder<> B(SI);

    Value *addr = SI->getPointerOperand();
    Value *funcStruct = SI->getValueOperand();
    Value *func = B.CreateExtractValue(funcStruct, 0);

    doMacPtr(M, B, addr, func);

    return true;
}

bool CCFI::checkVTableStore(Module &M, StoreInst *SI)
{
    Value *v = SI->getValueOperand();

    ConstantExpr *c = dyn_cast<ConstantExpr>(v);
    if (!c || c->getOpcode() != Instruction::GetElementPtr)
        return false;

    int i = 0;

    for (User::op_iterator I = c->op_begin(), IE = c->op_end(); I != IE; ++I) {
        Value *x = *I;

        if (i == 0 && strncmp(x->getName().data(), "_ZT", 3) != 0)
            break;

        i++;
    }

    if (i != 3)
        return false;

    doStoreCall(M, SI);
    return true;
}

void CCFI::doStoreCall(Module &M, StoreInst *SI)
{
    Value *addr = SI->getPointerOperand();
    Value *func = SI->getValueOperand();

    IRBuilder<> B(SI);

    doMacPtr(M, B, addr, func);
}

void CCFI::doMacPtr(Module &M, IRBuilder<> &B, Value *addr, Value *func)
{
    LLVMContext &ctx = M.getContext();

    Value *tmpAddr = B.CreatePtrToInt(addr, Type::getInt64Ty(ctx));
    Value *tmpFunc;
    if (func->getType() == Type::getInt64Ty(ctx))
        tmpFunc = func;
    else
        tmpFunc = B.CreatePtrToInt(func, Type::getInt64Ty(ctx));
    Value *tmpFuncType = tmpFunc;
    if (enableTypedPtr) {
	Value *funcHash = B.getInt64(hashFuncType(func->getType()));
	tmpFuncType = B.CreateXor(tmpFunc, funcHash);
    }

    Value *macptr = Intrinsic::getDeclaration(&M, Intrinsic::macptr);

#ifdef DEBUG_CHECKPTR
    macptr = M.getOrInsertFunction("__ccfi_debug_macptr",
					      Type::getIntNTy(ctx, 128),
					      Type::getInt64Ty(ctx),
					      Type::getInt64Ty(ctx),
						      NULL);
#endif

    B.CreateCall2(macptr, tmpFuncType, tmpAddr);
}

// Handle Loads

CCFI::CheckPoint CCFI::doLoad(Module &M, LoadInst *LI)
{
    CheckPoint cp;
    LLVMContext &ctx = M.getContext();

    Value *func = LI;
    Value *addr = LI->getPointerOperand();

    Instruction *ni = LI->getNextNode();
    IRBuilder<> B(ni);

    Value *tmpFunc = B.CreatePtrToInt(func, Type::getInt64Ty(ctx));
    Value *tmpAddr = B.CreatePtrToInt(addr, Type::getInt64Ty(ctx));

    cp.inst = LI;
    cp.insertionPt = ni;
    if (enableTypedPtr) {
	cp.hash = hashFuncType(func->getType());
    } else {
	cp.hash = 0;
    }
    cp.func = tmpFunc;
    cp.addr = tmpAddr;
    cp.isMethodPtr = false;

    return cp;
/*
    Value *checkptr = Intrinsic::getDeclaration(&M, Intrinsic::checkptr);
    Value *checkptr_isValid = B.CreateCall2(checkptr, tmpFunc, tmpAddr);

    Value *zeroValue = B.getInt64(0);
    Value *isNotValid = B.CreateICmpEQ(checkptr_isValid, zeroValue);

    return cast<Instruction>(isNotValid);*/
}

char CCFI::ID = 0;
static RegisterPass<CCFI> X("ccfifp", "CCFI pointer protection");

static void registerMyPass(const PassManagerBuilder &B,
                           PassManagerBase &PM) {
    if (getenv("CCFI_DISABLE_FP") != NULL)
        return;

    PM.add(new CCFI());
}

// This should run at the end
static RegisterStandardPasses
    RegisterMyPass(PassManagerBuilder::EP_ModuleOptimizerEarly,
                   registerMyPass);

static RegisterStandardPasses
    RegisterMyPass2(PassManagerBuilder::EP_EnabledOnOptLevel0,
                   registerMyPass);
