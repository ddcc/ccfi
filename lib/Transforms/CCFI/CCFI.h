/*
 * CCFI Function Pointer Protection
 */

#ifndef CCFI_H
#define CCFI_H

namespace llvm {

class CCFI : public ModulePass {
public:
    static char ID;
    CCFI();
    bool runOnModule(Module &M);
private:
    struct CheckPoint {
	Instruction *inst;
	Instruction *insertionPt;
	uint32_t hash;
	Value *func;
	Value *addr;
	bool isMethodPtr;
    };
    typedef SmallVector<int, 10> depth_t;
    bool enableTypedPtr;
    // Globals
    bool doGlobal(Module &M, Value &v, IRBuilder<> *B = NULL);
    bool doGlobal(Module &M, Value &v, Type *t, depth_t &depth, IRBuilder<> *B);
    void doGlobalCall(LoadInst *LI);
    void addGlobalMAC(Module &M, Value &v, Type *t, depth_t &depth, IRBuilder<> *b);
    // Global Constructor Block
    IRBuilder<> *getGCB(Module &M);
    void finishGCB();
    IRBuilder<> *gcb;
    // Basic Blocks
    bool doBasicBlock(Module &M, BasicBlock &BB);
    // Calls
    bool doCall(Module &M, CallInst *CI);
    // Extract Value
    CheckPoint doExtractValue(Module &M, ExtractValueInst *EV);
    // Stores
    bool doStore(Module &M, StoreInst *SI);
    bool checkMemberFPtrStore(Module &M, StoreInst *SI);
    bool checkVTableStore(Module &M, StoreInst *SI);
    bool checkVTTStore(Module &M, StoreInst *SI);
    void doStoreCall(Module &M, StoreInst *SI);
    // Loads
    CheckPoint doLoad(Module &M, LoadInst *LI);
    // Utils
    bool isMemFptr(Type *t);
    void doMacPtr(Module &M, IRBuilder<> &B, Value *addr, Value *func);
};

}

#endif /* CCFI_H */

