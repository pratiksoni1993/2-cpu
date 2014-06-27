#define DEBUG_TYPE "cti"
#include "AutoCrypt.h"

using namespace std;

char AutoCrypt::ID = 0;
static RegisterPass<AutoCrypt> Y("cti", "AutoCrypt Type Inference Analysis Pass (with getAnalysisUsage implemented)", false, false);

bool AutoCrypt::runOnModule(Module &M)
{
  bool fixed_point = false;   
  int old_length, new_length; 
  old_length =  new_length  = 0;
  fillFunctionMap();

  do
    {
      visit(M);     
      new_length = encrypted_variables.size();
      if(new_length == old_length) 
	{
	  fixed_point = true;
	}
      else
	{
	  old_length = new_length;
	}
    } while(!fixed_point);
  int flag=0;
  
  if(flag)
   Transform(&M);
  return false;
}


   

/********************Start of  Instruction's Visitor Functions**********************************/
// These functions perform the analysis part of the pass
// Each visited instruction is analysed to check whether it operates on encrypted values.
// A sensitive variable is inserted in the encrypted variables list
// A instruction operating on such a variable is inserted in the StubPointSet list

void  AutoCrypt :: visitModule(Module &M)
{
  //do nothing here
  // let the control go to the first function in the file
}


// Control comes here whenever the pass visits a function
// @F --> The function pointed by the pass
void AutoCrypt :: visitFunction(Function &F)
{ 
  // equivalent to a C function
  std::string fname = F.getName();                           // Name of the visited function
  int cnt, position;                                         // Counter and argument position
  std::string arg_name;                                      // Name of the function argument
  Function::arg_iterator i = F.arg_begin(), e = F.arg_end(); // Argument iterators
      
  if(!isVisited(fname))
    {
		
	//If not visited then reinitialize	
      cnt = 1;
      functionMap[fname]["return"] = 0;
      functionMap[fname]["transformed"] = 0;
      for(; i != e; ++i, ++cnt) 
	{
	  //make them unencrypted
	  functionMap[fname][convertInt_to_String(cnt)] = 0;
	}
    }
  else
    {
      for(; i != e; ++i) 
	{
     //If visited then check for newer additions to the encrypted list		
	  position = ((*i).getArgNo())+1;
	  if(functionMap[fname][convertInt_to_String(position)] == 1) 
	    {
		  //if the variable is encrypted insert it in the list
	      arg_name = get_enc_var(fname, (*i).getName());
	      insertEncryptedVariable(arg_name);
	    }
	}
    }
}


// Call Instruction visitor function
// This function gets called when the pass visits a call instruction


void AutoCrypt :: visitCallInst(CallInst &I)
{      

  Function *F = I.getCalledFunction();                               // Pointer to function called by instruction              
  std::string fname = (*F).getName();                                // Name of the called function
  
  std::string parentFName = (I).getParent()->getParent()->getName(); // Name of the parent function
  
  User::op_iterator oi = I.op_begin(), oe = I.op_end();              // Operand iterators
  Function::arg_iterator ai = F->arg_begin(), ae = F->arg_end();     // Argument interators
  std::string lhs_var = I.getName();                                 // Name of the left hand side of instruction
  
  int cnt, position;                                                 // Counter and argument position
  std::string opName;                                                // Name of the operand
  std::string actual_arg_name, actual_enc_var;                       // Original and Encrypted name of actual argument
  std::string formal_arg_name, formal_enc_var;                       // Original and Encrypted name of formal argument
  
  if( F == NULL) 
    {
      errs() << "encountered a indirect function call, skipping.......... \n";
      return;
    }

  // Check if the function is a library function or an internal function of the program
  if((*F).isDeclaration())
    {
      if(!isVisited(fname))
	{
	  functionMap[fname] = InnerMap();
	  functionMap[fname].insert(std::make_pair(get_enc_var(fname, "return"), 0));
	  return;
	}
      else
	{
	  cnt = 1;
	  for(; oi != oe; ++oi, ++cnt) {
	    if( functionMap[fname][convertInt_to_String(cnt)] == 1) 
	      {
		if(!(isa<ConstantInt>(*oi))) 
		  {
		    opName = (*oi)->getName();    
		    insertEncryptedVariable(get_enc_var(parentFName, opName));
		  }
		StubPointSet.insert(&I);
	      }

	    if(functionMap[fname]["return"] == 1)
	      {
		insertEncryptedVariable(get_enc_var(parentFName, lhs_var));
		StubPointSet.insert(&I);
	      }
	  }
	  return;  
	}
    }
  else 
    {
      if(isVisited(fname))
	{
	  cnt = 1;
	  for (;ai != ae; ++oi, ++ai, ++cnt) 
	    {
	      position = ((*ai).getArgNo())+1;

	      formal_arg_name = (*ai).getName();
	      formal_enc_var = get_enc_var(fname, formal_arg_name); 

	      actual_arg_name = (I).getOperand(position-1)->getName();
	      actual_enc_var = get_enc_var(parentFName, actual_arg_name);
	
	      // if it is global encrypted variable, add the variable to both the function list, called and callee

	      if(isEncrypted(actual_enc_var)) 
		{
		  functionMap[fname][convertInt_to_String(position)] = 1;
		  CallInsert(&I);
		}	

	      if( functionMap[fname][convertInt_to_String(cnt)] == 1) 
		{
		  if(!(isa<ConstantInt>(*oi))) 
		    {
		      opName = (*oi)->getName();    
		      insertEncryptedVariable(get_enc_var(parentFName, opName));
		    }
		  CallInsert(&I);
		}
	    }	
	  if(functionMap[fname]["return"] == 1)
	    {
	      insertEncryptedVariable(get_enc_var(parentFName, lhs_var));
	      CallInsert(&I);
	    }                    
	}
    }
}
    


// Return Instruction visitor function
// This function gets called when the pass visits a return instruction
void 
AutoCrypt :: visitReturnInst(ReturnInst &I) 
{
  std::string fname = (I).getParent()->getParent()->getName(); // Name of the parent function

  if(I.getReturnValue()) 
    {
      std::string ret_name = I.getOperand(0)->getName();
      ret_name = get_enc_var(fname, ret_name);
      if(isEncrypted(ret_name)) 
	{
	  functionMap[fname]["return"] = 1; 
	  StubPointSet.insert(&I);
	}
    }
}  
    

// PHI Instruction visitor function
// This function gets called when the pass visits a phi instruction
void
AutoCrypt :: visitPHINode(PHINode &I) 
{
  User::op_iterator i = I.op_begin(), e = I.op_end();         // Instruction operand iterator
  std::string fname = (I).getParent()->getParent()->getName();// Name of the parent function
  std::string opName, var;                                    // Operand name and encrypted variable name  

  for(; i != e; ++i) {
    if(!isa<ConstantInt>(*i))
      {                          
	opName = (*i)->getName();    
	var = get_enc_var(fname,opName);

	if(isEncrypted(var)) 
	  {
	    insertEncryptedVariable(get_enc_var(fname, I.getName()));
	    StubPointSet.insert(&I);
	    return;
	  }
      }
  }
}

// GetElementPtr Instruction visitor function
// This function gets called when the pass visits a GetElementPtr instruction
void 
AutoCrypt :: visitGetElementPtr(GetElementPtrInst &I)
{     

  const PointerType *PoTy = dyn_cast<PointerType>(I.getPointerOperandType()); // Pointer Type of the Operand
  const Type *Ty = PoTy->getElementType();                                    // Element Type of the Operand
  std::string fname = (I).getParent()->getParent()->getName();                // Name of the parent function
  std::string lhs = I.getName();                                              // Name of the L.H.S variable
  llvm::IRBuilder<> builder(getGlobalContext());

  if(isEncrypted(get_enc_var(fname, lhs)))
    {
      if (Ty->isStructTy())
	{
	  const StructType *StTy = dyn_cast<StructType>(Ty);
	  std::string strname = StTy->getName();
	  Structmap[strname] = dyn_cast<ConstantInt>(I.getOperand(2));
	  StubPointSet.insert(&I);
	}
    }
  if (Ty->isStructTy())
    {
      
      const StructType *StTy = dyn_cast<StructType>(Ty);
      std::string strname = StTy->getName();
      if(I.getNumOperands() == 3)      
	{
	  if(Structmap.find(strname) != Structmap.end() && Structmap[strname] == dyn_cast<ConstantInt>(I.getOperand(2)))
	    {
	      StubPointSet.insert(&I);
	      insertEncryptedVariable(get_enc_var(fname, lhs));
	    }
	}
    }
  else
    {
      LHSorRHS(&I);
    }
  //also check if the offset is encrypted_variable, if yes then generate this fact
  User::op_iterator i = I.idx_begin(), e = I.idx_end();
  std::string var, fact;

  for(; i != e; ++i)
    {
      if(!(isa<ConstantInt>(*i))) 
	{
	  var = get_enc_var(fname,(*i)->getName());
	  if(isEncrypted(var)) 
	    {
	      insertEncryptedVariable(get_enc_var(fname, lhs));
	      StubPointSet.insert(&I);
	    }
	}                
    }

}

// Alloca Instruction visitor function
// This function gets called when the pass visits a Alloca instruction
void 
AutoCrypt :: visitAllocaInst(AllocaInst &I) 
{     
  std::string fname = (I).getParent()->getParent()->getName();  // Name of the parent function
  std::string var = get_enc_var(fname,I.getName());             // Name of the encrypted variable
      
  if(isEncrypted(var))
    {
      StubPointSet.insert(&I);
    }

}

// Load Instruction visitor function
// This function gets called when the pass visits a Load instruction
void
AutoCrypt :: visitLoadInst(LoadInst &I) 
{     
  LHSorRHS(&I);

}

// Trunc Instruction visitor function
// This function gets called when the pass visits a Truncate instruction
void
AutoCrypt ::  visitTruncInst(TruncInst &I) 
{    
  LHSorRHS(&I);

}

// ZExt Instruction visitor function
// This function gets called when the pass visits a Zero extend instruction
void 
AutoCrypt :: visitZExtInst(ZExtInst &I) 
{
  LHSorRHS(&I);

}


// SExt Instruction visitor function
// This function gets called when the pass visits a Sign Extend instruction	
void 
AutoCrypt :: visitSExtInst(SExtInst &I) 
{
  LHSorRHS(&I);
}

	
// BitCast Instruction visitor function
// This function gets called when the pass visits a BitCast instruction		
void 
AutoCrypt :: visitBitCastInst(BitCastInst &I) 
{
  LHSorRHS(&I);
}

// Store Instruction visitor function
// This function gets called when the pass visits a Store instruction
void 
AutoCrypt :: visitStoreInst(StoreInst &I)
{     
  std::string fname = (I).getParent()->getParent()->getName();         // Name of the parent function

  std::string lhs, rhs;                                               // Name of L.H.S and R.H.S operands
  bool lhs_encrypt = false, rhs_encrypt = false;

  lhs = I.getOperand(0)->getName();
  rhs = I.getOperand(1)->getName();
  
  if(isEncrypted(get_enc_var(fname, lhs))) 
    {
      lhs_encrypt = true;
    }

  if(isEncrypted(get_enc_var(fname, rhs))) 
    {
      rhs_encrypt = true;
    }
  
  if(global_variables.find(rhs) != global_variables.end() )
    {
      insertEncryptedVariable(get_enc_var(fname, rhs));
      insertEncryptedVariable(get_enc_var(fname, lhs));
      StubPointSet.insert(&I);
      return;
    }


  if(lhs_encrypt && !rhs_encrypt) 
    {
      if(!isa<ConstantInt>(I.getOperand(1))) 
	{  
	  if((I).getOperand(1)->getValueID() == Value::GlobalVariableVal)
	    {
	      errs() << "Global Variable is" <<  (I).getOperand(1)->getName() << "\n";
	      global_variables.insert(rhs);
	  
	    }
	  insertEncryptedVariable(get_enc_var(fname, rhs));
	}
      StubPointSet.insert(&I);
      return;
    }

  if(rhs_encrypt && !lhs_encrypt) 
    {
      if(!isa<ConstantInt>(I.getOperand(1))) 
	{  
	  insertEncryptedVariable(get_enc_var(fname, lhs));
	}
      StubPointSet.insert(&I);
    }

  if(rhs_encrypt && lhs_encrypt) 
    {
      StubPointSet.insert(&I);
    }
}

// BinaryOperator Instruction visitor function
// This function gets called when the pass visits any instruction that uses a binary operator
void 
AutoCrypt :: visitBinaryOperator(BinaryOperator &I)
{
  std::string fname = (I).getParent()->getParent()->getName();           // Name of the parent function
  std::string lhs = I.getName();                                         // Name of the L.H.S variable
  std::string  op1, op2;                                                 // Name of the operands
  bool op1_enc = false, op2_enc = false;		

  op1 = I.getOperand(0)->getName();
  op2 = I.getOperand(1)->getName();

  if(isEncrypted(get_enc_var(fname, op1))) 
    {
      op1_enc = true;
    }

  if(isEncrypted(get_enc_var(fname, op2 ))) 
    {
      op2_enc = true;
    }
  
  // ADD, XOR --> If any one of the operands is encrypted, the lhs is encrypted, 
  // also encrypt the other non-encrypted variable
  if(I.getOpcode() == Instruction::Add || I.getOpcode() == Instruction::Xor) 
    {
      if(op1_enc || op2_enc) 
	{
	  insertEncryptedVariable(get_enc_var(fname, lhs));  
	  // generateFact(&I);
	  enc_type = "paillier";
	  ciphersize = 256;
	  StubPointSet.insert(&I);
	}
    }


  //ADD FADD SUB FSUB MUL FMUL SDIV UDIV FDIV XOR AND SHL LSHR ASHR
  // Cannot support instructions that work on floating point
  //If only one of the operands is encrypted, result is encrypted
  if(I.getOpcode() == Instruction::Add || I.getOpcode() == Instruction::FAdd || I.getOpcode() == Instruction::Sub || 
     I.getOpcode() == Instruction::FSub || I.getOpcode() == Instruction::Mul || I.getOpcode() == Instruction::FMul ||
     I.getOpcode() == Instruction::SDiv || I.getOpcode() == Instruction::UDiv || I.getOpcode() == Instruction::FDiv ||
     I.getOpcode() == Instruction::Xor || I.getOpcode() == Instruction::And || I.getOpcode() == Instruction::Shl ||
     I.getOpcode() == Instruction::LShr || I.getOpcode() == Instruction::AShr) 
    {
      if(isEncrypted(get_enc_var(fname, op1)) || isEncrypted(get_enc_var(fname, op2))) 
	{
	  insertEncryptedVariable(get_enc_var(fname, lhs));
	  enc_type = "paillier";
	  ciphersize = 256;
	  StubPointSet.insert(&I);
	}
    }                                                                                      
}
    
// ICmp Instruction visitor function
// This function gets called when the pass visits a Comparison instruction
void
AutoCrypt :: visitICmpInst(ICmpInst &I) 
{
  llvm::CmpInst::Predicate pr = I.getUnsignedPredicate();                         // Comparison Predicate
  std::string fname = (I).getParent()->getParent()->getName();                    // Name of the parent function
  std::string op1 = I.getOperand(0)->getName(), op2 = I.getOperand(1)->getName(); // Name of the operands
  switch(pr) 
    {
    case ICmpInst::ICMP_NE:
    case ICmpInst::ICMP_EQ:
    case ICmpInst::ICMP_UGT:
    case ICmpInst::ICMP_ULT: 
    case CmpInst::ICMP_UGE: 
    case CmpInst::ICMP_ULE: 
    case ICmpInst::ICMP_SGT:
    case ICmpInst::ICMP_SLT: 
    case CmpInst::ICMP_SGE: 
    case CmpInst::ICMP_SLE: 
      /* check if it is a pointer comparison, if yes, do nothing & return 
       */
      if((I.getOperand(0)->getType())->isPtrOrPtrVectorTy() && (I.getOperand(1)->getType())->isPtrOrPtrVectorTy()) 
	{
	  return;
	}

      if(isEncrypted(get_enc_var(fname, op1)) || isEncrypted(get_enc_var(fname, op2))) 
	{
	  enc_type = "search";
	  ciphersize = 20;
	  StubPointSet.insert(&I);

	  if(isEncrypted(get_enc_var(fname, op1)) && isEncrypted(get_enc_var(fname, op2))) 
	    {
	      return;
	    }

	  if(isEncrypted(get_enc_var(fname, op1)) && !(isa<ConstantInt>(I.getOperand(1)))) 
	    {
	      /* Op1 is encrypted, Op2 is a non constant --> Insert Op2 to encrypt table*/
	      insertEncryptedVariable(get_enc_var(fname, op2));
	      return;  
	    }

	  if(isEncrypted(get_enc_var(fname, op2)) && !(isa<ConstantInt>(I.getOperand(0)))) 
	    {
	      /* Op2 is encrypted, Op1 is a non constant --> Insert Op1 to encrypt table*/
	      insertEncryptedVariable(get_enc_var(fname, op1));
	      return;
	    }            
	}
      break;
    default:
      break;
    }
  return;
}

// Switch Instruction visitor function
// This function gets called when the pass visits a Switch instruction
void 
AutoCrypt :: visitSwitchInst(SwitchInst &I) 
{
  std::string fname = (I).getParent()->getParent()->getName();           // Name of the parent function
  std::string op1 = I.getOperand(0)->getName();                          // Name of the first operand

  if(isEncrypted(get_enc_var(fname, op1))) 
    {
      enc_type = "search";
      ciphersize = 20;
      StubPointSet.insert(&I);
    }
}

/********************END of Visit Instructions**********************************/

/* Begin of the transformation pass*/
/* This function instruments all the sensitive instructions saved in the StubPointSet and CallPointSet */
// @Mod --> Takes the module as input and iterates over all the instructions in the module
// If a instruction is present in the StubPointSet or CallPointSet
// - then that instruction is transformed to work on encrypted data.
// It explicitly looks for 'printf' and 'putchar' function, that output data from the file
// and transforms them

void
AutoCrypt :: Transform(Module* Mod)
{
  if(StubPointSet.empty())
    {
      return;   
    }
   
  std::set<Instruction*>::iterator it = StubPointSet.begin();  // Iterator for the StubPointSet 
  Module *M = (*it)->getParent()->getParent()->getParent();    // Module on which iteration is done
  Module::iterator i = M->begin(), e = M->end();               // Module iterator

  for(;i!=e;++i)
    {
      if(!(*i).isDeclaration())
	{
	  for (inst_iterator ii= inst_begin(*i), ie = inst_end(*i); ii != ie;)
	    {
	      Instruction *I = &*ii;
	      ++ii;

	      if(StubPointSet.find(I) != StubPointSet.end())
		{
		  modifyInstruction(I);
		}

	      if(CallInst *C = dyn_cast<CallInst>(I))
		{
		  if(C->getCalledFunction()->getName() == "putchar_unlocked")
		    {
		      modifyInstruction(I);
		    }

		  if(C->getCalledFunction()->getName() == "printf")
		    {
		      modifyInstruction(I);
		    }
		}
	    }
	}
    }  

  for(std::set<Instruction*>::iterator it = CallPointSet.begin(); it != CallPointSet.end(); it++)
    {
      modifyInstruction(*it);
    }
}

/* Depending on the instruction opcode, this functions modifies the instruction to work on encrypted data */
// @I --> Takes the instruction as input and modifies it depending on its instruction type
void
AutoCrypt :: modifyInstruction(Instruction *I)
{ 
  Module * M = I->getParent()->getParent()->getParent();
  LLVMContext *ctx = &M->getContext(); 
  llvm::IRBuilder<> builder(getGlobalContext());
  
  unsigned use_opcode, i, NumArgs, opcode = I->getOpcode();
  std::string fname = (*I).getParent()->getParent()->getName();           
  std::string lhs, rhs, calledName; 
  Type *t, *ElTy, *t0, *t1, *Newret;
  PointerType *PTy;
  Value *v, *v1, *v2, *des, *src;
  Instruction *L, *U, *Call, *S, *C;
  LoadInst *LI;
  Value::use_iterator u, ue, ul, ule;
  Constant* fun;
  FunctionType* Fty, *NewFty;
  std::vector<llvm::Type*> arg, ArgType;
  std::vector<llvm::Value*> Args;
  CallInst *CI, *New;
  StoreInst *St;
  Function *NF, *F;
  Function::arg_iterator beg, end, new_beg;
  int c, op;
  BinaryOperator *B;
  AllocaInst *All;


  switch(opcode)
    {
      
      /* If returned variable is sensitive, change its type to hold an encrypted value */
    case Instruction::Ret: 
      {
	rhs = (*I).getOperand(0)->getName();
	
	if(isEncrypted(get_enc_var(fname, rhs)))
	  {
	    t = (*I).getOperand(0)->getType();
	    
	    if(t != Type::getInt8PtrTy(*ctx))
	      {
		(*I).getOperand(0)->mutateType(Type::getInt8PtrTy(*ctx));
	      }
	  }
      }
      break;

      /* If the loaded variable is sensitive, change its type 
         If the loaded variable is further used in a Store instruction, then 
         call the memcpy function copy the loaded variable to the destination of Store instruction*/
    case Instruction::Load: 
      {
	PTy = dyn_cast<PointerType>(I->getOperand(0)->getType());
	ElTy = PTy->getElementType();
	lhs = (*I).getName();
	rhs = (*I).getOperand(0)->getName();

	u = (*I).use_begin();
	ue = (*I).use_end();
	
	if(EraseInstruction.find(I) != EraseInstruction.end())
	  {
	    I->eraseFromParent();
	  }
	else
	  {
	    (*I).mutateType(ElTy);
	    
	    for(;u!=ue;u++)
	      {
		U = dyn_cast<Instruction>(*u);
		
		if(U->getOpcode() == Instruction::Store
		   && I->getOperand(0)->getType() == Type::getInt8PtrTy(*ctx))
		  {
		    if(U->getOperand(1)->getType() == Type::getInt8PtrTy(*ctx)->getPointerTo())
		      {
			LI= new LoadInst(U->getOperand(1),"",I);
			des = LI;
		      }
		    
		    if(U->getOperand(1)->getType() == Type::getInt8PtrTy(*ctx))
		      {
			des = U->getOperand(1);
		      }
		    src = I->getOperand(0);

		    U->setOperand(0,src);

		    createMemcpy(des,src,M,U);
		    EraseInstruction.insert(U);
		    I->eraseFromParent();
		  }
	      }
	  }
      }
      break;

      /* Change the variable type if it is encrypted */
    case Instruction::Store: 
      {

	lhs = (*I).getOperand(0)->getName();
	rhs = (*I).getOperand(1)->getName();
	t0 = (*I).getOperand(0)->getType();
	t1 = (*I).getOperand(1)->getType();
	src = I->getOperand(0);
	des = I->getOperand(1);
	
	if(EraseInstruction.find(I) != EraseInstruction.end())
	  {
	    I->eraseFromParent();
	  }
	else
	  {
	    if(isEncrypted(get_enc_var(fname, rhs))||isEncrypted(get_enc_var(fname, lhs)))
	      {
		if(t0 == Type::getInt8PtrTy(*ctx) || t0->isIntegerTy() )
		  if(t0 != Type::getInt8PtrTy(*ctx) || t1 != Type::getInt8PtrTy(*ctx)->getPointerTo() )
		    { 
		      if(isa<Constant>(I->getOperand(0)))
			{
			  arg.push_back(I->getOperand(0)->getType());
			  llvm::ArrayRef<llvm::Type*>  arg_ref(arg);

			  Fty = FunctionType::get(builder.getInt8PtrTy(),arg_ref,false);  
			
			  if(enc_type == "search")
			    {
			      fun = M->getOrInsertFunction("getEncryption", Fty); 
			    }
			  if(enc_type == "paillier")
			    {
			      fun = M->getOrInsertFunction("getPaillier", Fty); 
			    }

			  Args.push_back(I->getOperand(0));
			  llvm::ArrayRef<llvm::Value*>  arg_val(Args);
			
			  CI =  CallInst::Create(fun, arg_val,"", I); 
			  I->setOperand(0, CI);
			
			}
		      else if(t0 == Type::getInt8PtrTy(*ctx) && t1 ==  Type::getInt8PtrTy(*ctx)->getPointerTo())
			{
			  break;
			}
		    
		      else if(t0 == Type::getInt8PtrTy(*ctx) && t1 ==  Type::getInt8PtrTy(*ctx))
			{
			  createMemcpy(des, src, M, I);
			  I->eraseFromParent();
			}   
		      else
			{
			  (*I).getOperand(0)->mutateType(Type::getInt8PtrTy(*ctx));
			  (*I).getOperand(1)->mutateType(Type::getInt8PtrTy(*ctx)->getPointerTo()); 
			}
		    }
	      }
	  }
      }
      break;
    
      /*If the variable is sensitive, change its type and allocate memory to hold the encrypted value */ 
    case Instruction::Alloca: 
      {
	lhs = I->getName();
	
	if(isEncrypted(get_enc_var(fname, lhs)))
	  {
	    if(dyn_cast<AllocaInst>(I)->getAllocatedType()->isIntegerTy() )
	      {
		I->mutateType(Type::getInt8PtrTy(*ctx)->getPointerTo());
		
		if(lhs.compare(0,3,"tmp") != 0)
		  {
		    
		    arg.push_back(builder.getInt32Ty());
		    llvm::ArrayRef<llvm::Type*>  arg_ref(arg);
		    Fty = FunctionType::get(builder.getInt8PtrTy(),arg_ref,false); 
		    fun  = M->getOrInsertFunction("malloc", Fty);
		    Args.push_back(builder.getInt32(ciphersize));
		    llvm::ArrayRef<llvm::Value*>  arg_val(Args);
		    
		    CI = CallInst::Create(fun, arg_val,"");
		    CI->insertAfter(I);
		    St = new StoreInst(CI,I);
		    St->insertAfter(CI);
		  }
	      }
	  }
      }
      break;

    case Instruction::Call: 
      {

	F = dyn_cast<CallInst>(I)->getCalledFunction();
	calledName = F->getName();
	bool store = false, cmp = false;

	if(!(F->isDeclaration()))
	  {
	    Fty = F->getFunctionType();
	    if(functionMap[calledName]["transformed"]!=1 && !(F->isDeclaration()))
	      {
		if(functionMap[calledName]["return"]==1)
		  {
		    Newret = Type::getInt8PtrTy(*ctx);
		  }
		else
		  {
		    Newret = F->getReturnType();
		  }
		    
		beg = F->arg_begin(), end = F->arg_end();
		c = 0;
		for( ; beg != end; ++beg, ++c)
		  {
		    if(functionMap[calledName][convertInt_to_String(c + 1)] == 1 && 
		       ((beg->getType()->isIntegerTy()) ||
			(beg->getType() == Type::getInt8PtrTy(*ctx))))
		      {
			ArgType.push_back(Type::getInt8PtrTy(*ctx));
		      }
		    else
		      {
			ArgType.push_back(Fty->getParamType(c));
		      }
		  }
 
		llvm::ArrayRef<llvm::Type*>  arg1ref(ArgType);
		NewFty = FunctionType::get(Newret,arg1ref,false); 
		NF = Function::Create(NewFty, F->getLinkage());
		      
		F->getParent()->getFunctionList().insert(F, NF);
		NF->takeName(F);
		NumArgs = NewFty->getNumParams();
		      
		NF->getBasicBlockList().splice(NF->begin(), F->getBasicBlockList());
		while (!F->use_empty())
		  {
		    CallSite CS(F->use_back());
		    Call = CS.getInstruction();
		    Args.assign(CS.arg_begin(), CS.arg_begin() + NumArgs);

		    for ( i = 0; i != Args.size(); ++i )
		      {
			Args[i]->mutateType(NewFty->getParamType(i));
		      }

		    New = CallInst::Create(NF, Args, "", Call);
		    New->setDebugLoc(Call->getDebugLoc());
		    Args.clear();
 
		    if (!Call->use_empty())		
		      {
			Call->replaceAllUsesWith(New);
		      }
		    New->takeName(Call);
		    Call->eraseFromParent();
		  }

		for (beg = F->arg_begin(), end = F->arg_end(),
		       new_beg = NF->arg_begin(); beg != end; ++beg, ++new_beg)
		  {
		    beg->replaceAllUsesWith(new_beg);
		    new_beg->takeName(beg);
		  }
		F->eraseFromParent();

	      }
	    functionMap[calledName]["transformed"] = 1;
	  }

	else
	  {
	    if(F->getName() == "getc_unlocked")
	      {
		u = (*I).use_begin(), ue = (*I).use_end();
		
		for(;u!=ue;u++)
		  {
		    U = dyn_cast<Instruction>(*u);
		    if(U->getOpcode() == Instruction::Store)
		      {
			S = dyn_cast<Instruction>(*u);
			store=true;
		      }
		    else if(U->getOpcode() == Instruction::ICmp)
		      {
			C = dyn_cast<Instruction>(*u); 
			cmp = true;
		      }
		    else
		      errs() << "remain" << *U << "\n";
		  }
		if(store)
		  {
		    LI = new LoadInst(S->getOperand(1),"",I);

		    arg.push_back(builder.getInt8PtrTy());
		    arg.push_back(builder.getInt32Ty());
		    arg.push_back(builder.getInt32Ty());
		    arg.push_back(I->getOperand(0)->getType());
 
		    llvm::ArrayRef<llvm::Type*>  arg_ref(arg);
		    Fty = FunctionType::get(builder.getInt32Ty(),arg_ref,false); 
		    fun = M->getOrInsertFunction("fread_unlocked", Fty);
		    
		    Args.push_back(LI);
		    Args.push_back(builder.getInt32(1));
		    Args.push_back(builder.getInt32(ciphersize));
		    Args.push_back(I->getOperand(0));
		    llvm::ArrayRef<llvm::Value*>  arg_val(Args);
		    CI = CallInst::Create(fun, arg_val, "size", I );

		    S->setOperand(0,builder.getInt32(1));
		    EraseInstruction.insert(S);
		   
		    if(cmp)
		      {
			if((C)->getOperand(1) == builder.getInt32(-1) || (C)->getOperand(1) == builder.getInt32(0))
			  {
			    (C)->setOperand(0, CI);
			    (C)->setOperand(1, builder.getInt32(0));
			  }
		      }
		  }
		I->eraseFromParent();
	      }
	    
	    if(F->getName() == "putchar_unlocked")
	      {
		if(isa<Constant>(I->getOperand(0)))
		  {
		    arg.push_back((I)->getOperand(0)->getType());
		    llvm::ArrayRef<llvm::Type*>  arg_ref(arg);
		    Fty = FunctionType::get(builder.getVoidTy(),arg_ref,false); 
		    fun = M->getOrInsertFunction("put_constant", Fty); 
		    
		    Args.push_back((I)->getOperand(0));
		    llvm::ArrayRef<llvm::Value*>  arg_val(Args);
		    CI =  CallInst::Create(fun, arg_val,"", dyn_cast<Instruction>(I)); 
		    (I)->setOperand(0,CI);
		    I->eraseFromParent();
		    break;
		  }
		
		arg.push_back(Type::getInt8PtrTy(*ctx));
		llvm::ArrayRef<llvm::Type*>arg_typep(arg);
		Fty = FunctionType::get(builder.getVoidTy(),arg_typep,false); 
		fun = M->getOrInsertFunction("fputs_enc", Fty); 
		
		I->getOperand(0)->mutateType(Type::getInt8PtrTy(*ctx));
		Args.push_back(I->getOperand(0));
		llvm::ArrayRef<llvm::Value*>arg_valuep(Args);
		CI  = CallInst::Create(fun , arg_valuep, "", I);
		I->eraseFromParent();
	      }

	    if(F->getName() == "printf")
	      {
		
		arg.push_back(builder.getVoidTy());
		llvm::ArrayRef<llvm::Type*>arg_typep(arg);
		Fty = FunctionType::get(builder.getVoidTy(),false); 
		fun = M->getOrInsertFunction("print_mark", Fty); 
		CI  = CallInst::Create(fun, "", I);
		
		CallInst *CI_after = CallInst::Create(fun, "", I);
		I->moveBefore(CI_after);
	      }
	  }
      }
      break;


    case Instruction::GetElementPtr: 
      { 

	if(isEncrypted(get_enc_var(fname,(*I).getOperand(0)->getName())))
	  {
	    if(I->getNumOperands() == 3)
	      {
		op = 2;
		v1 = (*I).getOperand(op);
	      }
	    else
	      {
		op =1;
		v1 = (*I).getOperand(op);
	      }

	    
	    if((isa<Constant>((*I).getOperand(op))))
	      {
		v1->mutateType(Type::getInt32Ty(*ctx));
		v2 = builder.getInt32(20);
	
		B = BinaryOperator::Create(Instruction::Mul,v1,v2,"",I);
		B->mutateType(Type::getInt32Ty(*ctx));
		I->setOperand(op,B);
	      }
	    
	    u = (*I).use_begin(), ue = (*I).use_end();
	    for(;u!=ue;u++)
	      {

		use_opcode = dyn_cast<Instruction>(*u)->getOpcode();

		if(use_opcode == Instruction::Load)
		  {
		    L = dyn_cast<Instruction>(*u);
		    if(L->getOperand(0)->getType() == Type::getInt8PtrTy(*ctx)->getPointerTo())
		      {
			break;
		      }

		    All = new AllocaInst(Type::getInt8PtrTy(*ctx),0,"temp",L);
		    LI = new LoadInst(All,"",L);
		   
		    arg.push_back(builder.getInt32Ty());
		    llvm::ArrayRef<llvm::Type*>  arg_refm(arg);
		    
		    Fty = FunctionType::get(builder.getInt8PtrTy(),arg_refm,false); 
		    fun = M->getOrInsertFunction("malloc", Fty);
		    
		    Args.push_back(builder.getInt32(ciphersize));
		    llvm::ArrayRef<llvm::Value*>  arg_valm(Args);

		    CI = CallInst::Create(fun, arg_valm,"",LI);
		    new StoreInst(CI, All, LI);

		    I->mutateType( Type::getInt8PtrTy(*ctx));
		    createMemcpy(cast<Value>(LI), I, M, dyn_cast<Instruction>(*u));

		    ul = (*L).use_begin(), ule = (*L).use_end();

		    for(;ul!=ule;ul++)
		      {
			for(i = 0 ; i < (**ul).getNumOperands(); i++)
			  {
			    U = dyn_cast<Instruction>(*ul);
			    if(L == (*ul)->getOperand(i))
			      (*ul)->setOperand(i,LI);
			    if(U->getOpcode() == Instruction::ZExt)
			      EraseInstruction.insert(U);
			  }
		      }
		    EraseInstruction.insert(L);
		  }
		  
		if(use_opcode == Instruction::Store)
		  {
		    if(I == (*u)->getOperand(1))
		      {
			U = dyn_cast<Instruction>(*u);
			if(isa<Constant>((*u)->getOperand(0)))
			  {
			    arg.push_back((*u)->getOperand(0)->getType());
			    llvm::ArrayRef<llvm::Type*>  arg_ref(arg);
			    Fty = FunctionType::get(builder.getInt8PtrTy(),arg_ref,false); 
			    if(enc_type == "search")
			      {
				fun = M->getOrInsertFunction("getEncryption", Fty); 
			      }
			    if(enc_type == "paillier")
			      {
				fun = M->getOrInsertFunction("getPaillier", Fty); 
			      }
			    
			    Args.push_back((*u)->getOperand(0));
			    llvm::ArrayRef<llvm::Value*>  arg_val(Args);
			    CI =  CallInst::Create(fun, arg_val,"", dyn_cast<Instruction>(*u)); 
			    (*u)->setOperand(0, CI);
			  }
			else if((*u)->getOperand(0)->getType() == Type::getInt8PtrTy(*ctx) 
				&& (*u)->getOperand(1)->getType() == Type::getInt8PtrTy(*ctx)->getPointerTo())
			  break;
			
			src = (*u)->getOperand(0);
			
			if(src->getType() != Type::getInt8PtrTy(*ctx))
			  {
			    src->mutateType(Type::getInt8PtrTy(*ctx));
			  }

			I->mutateType( Type::getInt8PtrTy(*ctx));
			des = I;
			L = dyn_cast<Instruction>(*u);
			createMemcpy(des, src, M, dyn_cast<Instruction>(*u));
			
			ul = (*L).use_begin(), ule = (*L).use_end();
 			for( ; ul != ule; ul++)
			  {
			    for(i = 0 ; i < (**ul).getNumOperands(); i++)
			      {
				if(L == (*ul)->getOperand(i))
				  {
				    (*ul)->setOperand(i,des);
				  }
			      }
			  }

			EraseInstruction.insert(L);
		      }
		  }
	      }
	  }
      }
      
      break;
    case Instruction::Trunc: 
      {
	v = (*I).getOperand(0);
	u = (*I).use_begin();
	ue = (*I).use_end();
	
	if(isEncrypted(get_enc_var(fname,(*I).getOperand(0)->getName())))
	  {
	    (*v).mutateType(Type::getInt8PtrTy(*ctx));
	    
	    for( ; u != ue; u++)
	      {
		for(i = 0 ; i < (**u).getNumOperands(); i++)
		  {
		    if(I == (*u)->getOperand(i))
		      {
			(*u)->setOperand(i,v);
		      }
		  }
	      }
	  
	    (*I).eraseFromParent();
	  }
      }
      break;
	  
    case Instruction::SExt:
    case Instruction::ZExt:
      {
	u = (*I).use_begin();
	ue = (*I).use_end();
	v = (*I).getOperand(0);
	if(EraseInstruction.find(I) != EraseInstruction.end())
	  {
	    for( ; u != ue; u++)
	      {
		for(i = 0 ; i < (**u).getNumOperands(); i++)
		  {
		    if(I == (*u)->getOperand(i))
		      {
			(*u)->setOperand(i, v);
		      }
		  }
	      }
	    
	    I->eraseFromParent();
	    break;
	  }
	
	(*v).mutateType(Type::getInt8PtrTy(*ctx));
	u = (*I).use_begin();
	for(; u != ue; u++)
	  {
	    for(i = 0 ; i < (**u).getNumOperands(); i++)
	      {
		if(I == (*u)->getOperand(i))\
		  {
		    (*u)->setOperand(i,v);
		  }
	      }
	  }
	(*I).eraseFromParent();
      }
      break;
      
    case Instruction::ICmp: 
      { 
	lhs  = I->getOperand(0)->getName();
	CmpInst * cmpInstPtr = dyn_cast<CmpInst>(I);
	unsigned predict = cmpInstPtr->getPredicate();

	if(lhs.compare(0,4,"size") == 0)
	  {
	    break;
	  }

	arg.push_back(builder.getInt8PtrTy());
	arg.push_back(builder.getInt32Ty());
    	llvm::ArrayRef<llvm::Type*>  argsRef(arg);
	Fty = FunctionType::get(builder.getInt1Ty(),argsRef, false); 
	fun = M->getOrInsertFunction("compare", Fty); 
	   
	Args.push_back(I->getOperand(0));
	Args.push_back(I->getOperand(1)); 
	llvm::ArrayRef<llvm::Value*>  argsref(Args);

	CI =  CallInst::Create(fun, argsref,"", I); 
	I->setOperand(0,CI);

	switch(predict) 
	  {
	  case CmpInst::ICMP_EQ:
	    {
	      v =  builder.getTrue();
	      I->setOperand(1,v);
	      break;
	    }
	    
	  case CmpInst::ICMP_NE:
	    {
	      v =  ConstantInt::get(Type::getInt1Ty(*ctx), true);
	      I->setOperand(1,v);
	      break;
	    }
	  default:
	    break;
	  }
      }
      break;

    case Instruction::AShr: 
    case Instruction::LShr: 
      {
	if(isa<Constant>(I->getOperand(1)))
	  {
	    createPaillierFunc(I->getOperand(0),I->getOperand(1),"encrypt_shr",I);
	    I->eraseFromParent();
	  }
	else
	  errs() << "*** Not Supported***\n";
	break;
    
      case Instruction::And: 
	{
	  if(isa<Constant>(I->getOperand(1)))
	    {
	      createPaillierFunc(I->getOperand(0),I->getOperand(1),"encrypt_and",I);
	      I->eraseFromParent();
	    }
	  else
	    errs() << "*** Not Supported***\n";
	}
	break;
    
      case Instruction::Shl: 
	if(isa<Constant>(I->getOperand(1)))
	  {
	    createPaillierFunc(I->getOperand(0),I->getOperand(1),"encrypt_shl",I);
	    I->eraseFromParent();
	  }
	else
	  errs() << "*** Not Supported***\n";
      }
      break;
    
    case Instruction::Add: 
      {
	if(!(isa<Constant>(I->getOperand(1))))
	  {
	    std::vector<Type*> arg;
	    arg.push_back(builder.getInt8PtrTy());
	    arg.push_back(builder.getInt8PtrTy());

	    llvm::ArrayRef<Type*>argtype(arg);
	    Fty = FunctionType::get(builder.getInt8PtrTy(),argtype,false);
	    fun  = M->getOrInsertFunction("encrypt_add",Fty);
	    std::vector<Value*> Args;
	    Args.push_back(I->getOperand(0));
	    Args[0]->mutateType(Type::getInt8PtrTy(*ctx));
	    Args.push_back(I->getOperand(1));
	    Args[1]->mutateType(Type::getInt8PtrTy(*ctx));
	    llvm::ArrayRef<Value*>argvalue(Args);

	    CI = CallInst::Create( fun, argvalue, "", I);
	    ul = (*I).use_begin(), ule = (*I).use_end();
	    
	    for(;ul!=ule;ul++)
	      {
		for(i =0 ; i< (**ul).getNumOperands();i++)
		  {
		    if(I == (*ul)->getOperand(i))
		      {
			(*ul)->setOperand(i,CI);
		      }
		  }
	      }
	    I->eraseFromParent();
	  }
	else
	  {
	    createPaillierFunc(I->getOperand(0),I->getOperand(1),"encrypt_add_const",I);
	  }
      }
      break;

    default:
      errs() << "in default" << *I << "\n";
    }

}

// End of transformation functions 


// Beginning of helper functions

/* get_enc_var: Appends the function name and operand name 
   @fname, @var: First and second operands to concat. 
*/
std::string
AutoCrypt :: get_enc_var(std::string fname, std::string var) 
{
  return (fname + "_" + var);
}

/* Returns true if a function is visited / analysed already */
// @fname --> Function name to check if it is already analysed
bool 
AutoCrypt ::isVisited(std::string fname) 
{
  return (functionMap.find(fname) != functionMap.end());
}

/* Returns true if a variable is marked sensitive */
// @varname --> Checks whether varname is presented in the encrypted list
bool
AutoCrypt:: isEncrypted(std::string varname) 
{
  return (encrypted_variables.find(varname) != encrypted_variables.end());
}

char AutoCrypt:: typeEncrypted(std::string varname)
{
  char c = t_encrypted_variables[varname];
  return c;
}

/* Inserts the variable in the encrypted variables list */
// @enc_var_name --> Inserts this variable name to encrypted list and set the mode as "i" as default
void AutoCrypt :: insertEncryptedVariable(std::string enc_var_name) 
{
  if((*enc_var_name.rbegin()) != '_') 
    {
      encrypted_variables.insert(enc_var_name);
      t_encrypted_variables.insert(std::make_pair(enc_var_name, 'i'));
    
      			
    }
}

void AutoCrypt :: changeModeEncryptiontoBIT(std::string enc_var_name)
{
   t_encrypted_variables[enc_var_name] = 'b';
}

void AutoCrypt :: changeModeEncryptiontoINT(std::string enc_var_name)
{
   t_encrypted_variables[enc_var_name] = 'i';
}

/* Inserts a Call instrunction in the sensitive instructions list*/
// @I --> Call Instruction that has to be inserted the CallPointSet data structure
void
AutoCrypt :: CallInsert(Instruction *I)
{
  std::string fname = dyn_cast<CallInst>(I)->getCalledFunction()->getName();
  if(CallPointSet.empty())
    {
      CallPointSet.insert(I);
      ChangedCallIns.insert(fname);
    }
  else
    {
      if(ChangedCallIns.find(fname) == ChangedCallIns.end())
	{
	  CallPointSet.insert(I);
	  ChangedCallIns.insert(fname);
	}
    }
}
    
/* Converts an integer to string. Used in Map data  structures*/
// @number --> integer value which has to be converted to string
std::string 
AutoCrypt ::convertInt_to_String(int number)
{
  std::stringstream ss;
  ss << number;
  return ss.str();
}

/* If variable used is a sensitive global variable
   - then add both LHS and RHS to encrypted variables list
   If any of the variables is in encrypted list
   - then add the other variable to that list
   Add the instruction to StubPointSet */
void 
AutoCrypt :: LHSorRHS(Instruction *I) 
{
  std::string fname = (*I).getParent()->getParent()->getName();           
  std::string lhs = (*I).getName(), rhs = (*I).getOperand(0)->getName();
  
  if (global_variables.find(rhs) != global_variables.end())
    {
      insertEncryptedVariable(get_enc_var(fname, rhs));
      insertEncryptedVariable(get_enc_var(fname, lhs));
      StubPointSet.insert(I);
      return;
    }
  
  if(isEncrypted(get_enc_var(fname, lhs)) && !isEncrypted(get_enc_var(fname, rhs))) 
    {
      if((*I).getOperand(0)->getValueID() == Value::GlobalVariableVal)
	{
	  global_variables.insert(rhs);
	}
  
      insertEncryptedVariable(get_enc_var(fname, rhs));
      StubPointSet.insert(I);
      return;
    }
  
  if(isEncrypted(get_enc_var(fname, rhs)) && !isEncrypted(get_enc_var(fname, lhs))) 
    {
      insertEncryptedVariable(get_enc_var(fname, lhs));
      StubPointSet.insert(I);
    }

  if(isEncrypted(get_enc_var(fname, rhs)) && isEncrypted(get_enc_var(fname, lhs))) 
    {
      StubPointSet.insert(I);
    }			
}

/* Inserts a call to memcpy function*/
// @des --> destination value for memcpy
// @src --> source value for memcpy
// @M --> Module name
// @I --> Instruction before which the memcpy function is to be inserted
void 
AutoCrypt :: createMemcpy(Value* des, Value* src, Module *M, Instruction *I)
{
  llvm::IRBuilder<> builder(getGlobalContext());
  std::vector<llvm::Type*> arg;

  arg.push_back(builder.getInt8PtrTy());
  arg.push_back(builder.getInt8PtrTy());
  arg.push_back(builder.getInt32Ty());
  arg.push_back(builder.getInt32Ty());
  arg.push_back(builder.getInt1Ty());

  llvm::ArrayRef<llvm::Type*>  arg_ref(arg);
  FunctionType* Fty = FunctionType::get(builder.getVoidTy(),arg_ref,false); 
  Constant* fun = M->getOrInsertFunction("llvm.memcpy.p0i8.p0i8.i32", Fty);
  Value *len = builder.getInt32(ciphersize);
  Value *align = builder.getInt32(1);
  Value *volat = builder.getFalse();
		
  std::vector<llvm::Value*> Args;    
  Args.push_back(des);
  Args.push_back(src);
  Args.push_back(len);
  Args.push_back(align);
  Args.push_back(volat);
  llvm::ArrayRef<llvm::Value*>  arg_val(Args);

  CallInst::Create(fun, arg_val,"",I );

}
    
/*Insert Paillier operation functions depending on the function name */
/* Creates a call to the appropriate  paillier function depending on the instruction type */

void
AutoCrypt :: createPaillierFunc( Value *op1, Value *op2, StringRef name, Instruction *I)
{
  llvm::IRBuilder<> builder(getGlobalContext());
  Module *M = I->getParent()->getParent()->getParent();
  LLVMContext *ctx = &M->getContext(); 

  std::vector<Type*> type;
  type.push_back(builder.getInt8PtrTy());
  type.push_back(builder.getInt32Ty());
  llvm::ArrayRef<Type*> argtype(type);

  std::vector<Value*> value;
  value.push_back(op1);
  value[0]->mutateType(Type::getInt8PtrTy(*ctx));

  value.push_back(op2);
  value[1]->mutateType(Type::getInt32Ty(*ctx));
  llvm::ArrayRef<Value*> argvalue(value);
 
  FunctionType *Fty = FunctionType::get(builder.getInt8PtrTy(), argtype, false);
  Constant* fun  = M->getOrInsertFunction(name, Fty);
  CallInst *CI = CallInst::Create(fun,argvalue,"",I);

  Value::use_iterator ub = (*I).use_begin(), ue = (*I).use_end();
  for(;ub!=ue;ub++)
    {
      for(unsigned i = 0 ; i< (**ub).getNumOperands(); i++)
	{
	  if(I == (*ub)->getOperand(i))
	    (*ub)->setOperand(i,CI);
	}
    }
}

/* Fill the functionMap for functions which take sensitive variables as inputs */
void 
AutoCrypt :: fillFunctionMap() 
{

  //full_read
  functionMap["full_read"]["return"] = 0;
  functionMap["full_read"]["1"] = 0;//fd
  functionMap["full_read"]["2"] = 1;//buff
  functionMap["full_read"]["3"] = 0;//count

  //safe_read
  functionMap["safe_read"]["return"] = 0;
  functionMap["safe_read"]["1"] = 0;//fd
  functionMap["safe_read"]["2"] = 1;//buff
  functionMap["safe_read"]["3"] = 0;//count

  //readlinebuffer
  functionMap["readlinebuffer"]["return"] = 1;
  functionMap["readlinebuffer"]["1"] = 1;//linebuffer
  functionMap["readlinebuffer"]["2"] = 0;//filestream

  //readlinebuffer_delim, added for uniq
  functionMap["readlinebuffer_delim"]["return"] = 0;
  functionMap["readlinebuffer_delim"]["1"] = 1;//linebuffer
  functionMap["readlinebuffer_delim"]["2"] = 0;//filestream
  functionMap["readlinebuffer_delim"]["3"] = 1;//delimiter

  //getc
  functionMap["getc_unlocked"]["return"] = 1;      
  functionMap["getc_unlocked"]["1"] = 0;//istream

  //fgetc
  functionMap["fgetc_unlocked"]["return"] = 1;      
  functionMap["fgetc_unlocked"]["1"] = 0;//filestream

  //fread
  functionMap["fread_unlocked"]["return"] = 0;      
  functionMap["fread_unlocked"]["1"] = 1;//buffer_ptr
  functionMap["fread_unlocked"]["2"] = 0;//size
  functionMap["fread_unlocked"]["3"] = 0;//count
  functionMap["fread_unlocked"]["4"] = 0;//filestream

  //memchar, add to stubds for datalog
  functionMap["memchr"]["return"] = 1;
  functionMap["memchr"]["1"] = 1;
  functionMap["memchr"]["2"] = 1;
  functionMap["memchr"]["3"] = 0;

  //re_search, added for nl
  functionMap["re_search"]["return"] = 0;
  functionMap["re_search"]["1"] = 1;
  functionMap["re_search"]["2"] = 1;

  //mbrtowc
  functionMap["mbrtowc"]["return"] = 0;
  functionMap["mbrtowc"]["1"] = 1;
  functionMap["mbrtowc"]["2"] = 1;
  functionMap["mbrtowc"]["3"] = 0;
  functionMap["mbrtowc"]["4"] = 0;


  //getndelim2, added for cut
  functionMap["getndelim2"]["return"] = 0;
  functionMap["getndelim2"]["1"] = 1;
  functionMap["getndelim2"]["2"] = 0;
  functionMap["getndelim2"]["3"] = 0;
  functionMap["getndelim2"]["4"] = 0;
  functionMap["getndelim2"]["5"] = 0;
  functionMap["getndelim2"]["6"] = 0;//0?                
  functionMap["getndelim2"]["7"] = 0;

  //fread_file, added for shuf, ptx
  functionMap["fread_file"]["return"] = 1;
  functionMap["fread_file"]["1"] = 0;
  functionMap["fread_file"]["2"] = 0;

  //read_file, added for ptx
  functionMap["read_file"]["return"] = 1;
  functionMap["read_file"]["1"] = 0;
  functionMap["read_file"]["2"] = 0;

}
