
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


using namespace llvm;

class AutoCrypt : public ModulePass, public InstVisitor<AutoCrypt> {
 public:
  static char ID;

  /* Data structures used in the pass */
  std::set<std::string> functions_called_declared;
  std::set<std::string> functions_called_lib;
  std::set<std::string> instructions_called;

  typedef  std::map<std::string, int> InnerMap;
  typedef  std::map<std::string, InnerMap> NestedMap;
  /* FunctionMap to save the mapping of visited functions and their arguments */
  /*   The InnerMap saves maps the arguments to 1 or 0 depending on whether it */
  /*   is sensitive or not */
  NestedMap functionMap;
  
  /* Saves the struct name and the field number which is to be encrypted  */
  std::map< std::string, ConstantInt*> Structmap;
  
  /* A set of all variables that are sensitive and need to be encrypted */  
  std::set<std::string> encrypted_variables;
  
  std::map<std::string,char> test;
  /*Mapping of variables to their encrypted mode*/ 
  /* i for integer (default)*/
  /* b for bitwise*/
  std::map<std::string,char> t_encrypted_variables;
  
  /* A set of all global variables that are sensitive */
  std::set<std::string> global_variables;

  /* A set of all the instructions that operate on encrypted operands */
  std::set<Instruction*> StubPointSet;

  /* A set of all call instructions that pass encrypted variables as arguments */
  std::set<Instruction*> CallPointSet;

  /* A set of all instructions that need to be removed during the transformation pass */
  std::set<Instruction*> EraseInstruction;
  
  /* A set of Call instructions that have already been modified to work on encrypted inputs */
  std::set<std::string>ChangedCallIns;

  std::string ErrorInfo;
  
  /* Holds the encryption type --> search or paillier */
  std::string enc_type;
  
  /* Holds the ciphertext size depending on the encryption scheme */
  int ciphersize;
  bool open64;

 AutoCrypt() : ModulePass(ID) {}
  virtual bool runOnModule(Module &M);

  /*Start of  Instruction's Visitor Functions */
  /* These functions perform the analysis part of the pass */
  /* Each visited instruction is analysed to check whether it operates on encrypted values. */
  /* A sensitive variable is inserted in the encrypted variables list */
  /* A instruction operating on such a variable is inserted in the StubPointSet list */
  virtual void visitModule(Module &M);
  virtual void visitFunction(Function &F);
  virtual void visitCallInst(CallInst &I);
  virtual void visitReturnInst(ReturnInst &I);
  virtual void visitPHINode(PHINode &I);
  virtual void visitGetElementPtr(GetElementPtrInst &I);
  virtual void visitAllocaInst(AllocaInst &I);
  virtual void visitLoadInst(LoadInst &I);
  virtual void visitTruncInst(TruncInst &I);
  virtual void visitSExtInst(SExtInst &I);
  virtual void visitZExtInst(ZExtInst &I);
  virtual void visitBitCastInst(BitCastInst &I);
  virtual void visitStoreInst(StoreInst &I);
  virtual void visitBinaryOperator(BinaryOperator &I);
  virtual void visitICmpInst(ICmpInst &I);
  virtual void visitSwitchInst(SwitchInst &I);

  /* Begin of the transformation pass*/
  /*Modifies all the instruction that work on encrypted data*/
  virtual void Transform(Module* Mod);
  virtual void modifyInstruction(Instruction *I);

  // Beginning of helper functions

  /* get_enc_var: Appends the function name and operand name 
     @fname, @var: First and second operands to concat. 
  */
  virtual std::string get_enc_var(std::string fname, std::string var);

  /* Returns true if a function is visited / analysed already */
  // @fname --> Function name to check if it is already analysed
  virtual bool isVisited(std::string fname);

  /* Returns true if a variable is marked sensitive */
  // @varname --> Checks whether varname is presented in the encrypted list
  virtual bool isEncrypted(std::string varname);
  virtual void reportAnalysis();
 /*Returns encrypted mode if a variable is marked sensitive*/
  virtual char typeEncrypted(std::string varname);

 /*Changes the encryption modes of the encrypted_variables*/

  virtual void changeModeEncryptiontoBIT(std::string enc_var_name);
  virtual void changeModeEncryptiontoINT(std::string enc_var_name);

  /* Inserts the variable in the encrypted variables list */
  // @enc_var_name --> Inserts this varibale name to encrypted 
  virtual void insertEncryptedVariable(std::string enc_var_name);

  /* Inserts a Call instrunction in the sensitive instructions list*/
  // @I --> Call Instruction that has to be inserted the CallPointSet data structure
  virtual void CallInsert(Instruction *I);

  /* Converts an integer to string. Used in Map data  structures*/
  // @number --> integer value which has to be converted to string
  virtual std::string convertInt_to_String(int number);


  /* If variable used is a sensitive global variable
     - then add both LHS and RHS to encrypted variables list
     If any of the variables is in encrypted list
     - then add the other variable to that list
     Add the instruction to StubPointSet */
  virtual void LHSorRHS(Instruction *I);

  /* Inserts a call to memcpy function*/
  // @des --> destination value for memcpy
  // @src --> source value for memcpy
  // @M --> Module name
  // @I --> Instruction before which the memcpy function is to be inserted
  virtual void createMemcpy(Value* des, Value* src, Module *M, Instruction *I);

  /* Creates a call to the appropriate  paillier function depending on the instruction type */
  virtual void createPaillierFunc( Value *op1, Value *op2, StringRef name,Instruction *I);

  /* Fill the functionMap for functions which take sensitive variables as inputs */
  virtual void fillFunctionMap();

};
