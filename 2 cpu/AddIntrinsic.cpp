
/*
#include "llvm/Pass.h"
#include "llvm/Function.h"
#include "llvm/Instructions.h"
#include "llvm/Module.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/Passes.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Debug.h"
#include "llvm/DIBuilder.h"
#include "llvm/DebugInfo.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/Support/InstIterator.h"
#include "llvm/Support/InstVisitor.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/raw_os_ostream.h"
#include "llvm/Assembly/Writer.h"
#include "llvm/IRBuilder.h"
#include <string>
#include <sstream>
#include <map>
#include <set>
#include <iterator>
*/

#include "llvm/Module.h"
#include "llvm/Function.h"
#include "llvm/PassManager.h"
#include "llvm/CallingConv.h"
#include "llvm/Analysis/Verifier.h"
#include "llvm/Assembly/PrintModulePass.h"
#include "llvm/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Intrinsics.h"



using namespace llvm;

Module* makeLLVMModule();

int main(int argc, char**argv) {
  Module* Mod = makeLLVMModule();

  verifyModule(*Mod, PrintMessageAction);

  PassManager PM;
  PM.add(createPrintModulePass(&outs()));
  PM.run(*Mod);

  delete Mod;
  return 0;
}

Module* makeLLVMModule() {
  // Module Construction
  Module* mod = new Module("test", getGlobalContext());

Constant* c = mod->getOrInsertFunction("mul_add",
  /*ret type*/                           IntegerType::get(getGlobalContext(),32),
IntegerType::get(getGlobalContext(),32),
IntegerType::get(getGlobalContext(),32),
IntegerType::get(getGlobalContext(),32),
  /*args*/                           
  /*varargs terminated with null*/       NULL);
  
  Function* mul_add = cast<Function>(c);
  mul_add->setCallingConv(CallingConv::C);

 Function::arg_iterator args = mul_add->arg_begin();
  Value* x = args++;
  x->setName("x");
  Value* y = args++;
  y->setName("y");
  Value* z = args++;
  z->setName("z");



  BasicBlock* block = BasicBlock::Create(getGlobalContext(), "entry", mul_add);
  IRBuilder<> builder(block);

  Value* tmp = builder.CreateBinOp(Instruction::Mul,x, y, "tmp");
  Value* tmp2 = builder.CreateBinOp(Instruction::Add,tmp, z, "tmp2");
  std::vector<Type *> arg_type;
  
  Function *fun = Intrinsic::getDeclaration(mod, Intrinsic::x86_addenc_32);
  tmp2 = builder.CreateCall2(fun,tmp,z);

  builder.CreateRet(tmp2);
  
  return mod;
}

