#-*- coding=utf-8 -*-
from unicorn import *
from unicorn import arm_const
from unicorn.arm_const import *
from capstone import *
from capstone.arm import *
from keystone import *
def hook_code(uc, address, size, user_data):
	global FindFlag
	global Finding
	global JMP_PC
	ban_ins = ["bl"]
	#print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" %(address, size))
	
	for ins in md.disasm(bin1[address:address+size],address):
		print(">>> Tracing instruction at 0x%x, instruction size = 0x%x" % (address, size))
		print(">>> 0x%x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
		print("")


		flag_pass = False
		for b in ban_ins:
			if ins.mnemonic.find(b) != -1:
				flag_pass = True
				break


	if flag_pass:
		print("will pass 0x%x:\t%s\t%s" % (ins.address, ins.mnemonic, ins.op_str))
		uc.reg_write(UC_ARM_REG_PC, address + size)
	return
def hook_mem_access(uc,type,address,size,value,userdata):
	pc = uc.reg_read(UC_ARM_REG_PC)
	print('pc:%x type:%d addr:%x size:%x' % (pc,type,address,size))
	#uc.emu_stop()
	return False
def hook_error(uc,type,address,size,value,userdata):
	pc = uc.reg_read(UC_ARM_REG_PC)
	print('pc:%x type:%d addr:%x size:%x' % (pc,type,address,size))
	#uc.emu_stop()
	return False
FindFlag=0
Finding=0
JMP_PC={}
md = Cs(CS_ARCH_ARM,CS_MODE_ARM)
md.detail = True #enable detail analyise
offset = 0x3D4 #function start
end = 0x600	#function end
f=open('C:/Users/wei/Desktop/KanXueCTF/unicorn/test_arm','rb')
bin1 = f.read()
f.close()
mu = Uc(UC_ARCH_ARM, UC_MODE_ARM)
#init stack
mu.mem_map(0x80000000,0x10000 * 8)

mu.mem_map(0, 4 * 1024 * 1024)
mu.mem_write(0,bin1)
mu.reg_write(UC_ARM_REG_SP, 0x80000000 + 0x10000 * 6)

mu.reg_write(UC_ARM_REG_LR, end)#retn addr

mu.hook_add(UC_HOOK_CODE, hook_code)
mu.hook_add(UC_HOOK_MEM_UNMAPPED,hook_mem_access)
#mu.hook_add(UC_ERR_HOOK,hook_error)
mu.emu_start(offset,end)

