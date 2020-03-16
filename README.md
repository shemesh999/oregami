# Oregami
> """  
> What is this register used for?  
> Hmm.. I'll just rename it to veryuniquename, do a textual search, and find all references!  
> Ok.. Waiting for the search to end.. any minute now.. Done!  
> Now I just need to understand which of the search result is relevant to the current usage frame of the register.  
> Shouldn't be too hard, right?  
> """

If this happened to you (perhaps more than once), you are in for a treat!  
Just Shift-X, and your troubles will go away!  

You may also re(g)name the register in the usage frame. Just Shift-N, and follow instructions!  
Also - instead of changing the types of all the usages to a certain type, just Shift-T once.  

Note: Sometimes there is already another plugin using Shift-T. Remove that plugin - you never used it before anyway :-).  

## Installation
### Prerequisites
This plugin uses sark to interact with the IDA scripts in a comfortable way, and cachetools to cache the frame scan which makes this a whole of a lot faster.
 
[For python2]  
pip install sark  
pip install cachetools  

[For python3]  
If using python3 variant of IDA, you should instead run:  
pip3 install -U git+https://github.com/tmr232/Sark.git#egg=Sark  
pip3 install cachetools

### Clone the repo
git clone https://github.com/shemesh999/oregami

### Plugin installation
The sark codebase offers many plugins. One of them is:
https://github.com/tmr232/Sark/blob/master/plugins/plugin_loader.py

We recommend copying it to your plugins directory and then run IDA once with administrator privilages (so it can create the plugins.list files).  
After doing so, you can add new plugins by adding the path to them to one of the plugins.list files created (eg. one is created in the cfg
folder of IDA)

Now, add to one of the plugins.list files:  
FULLPATH\oregami\oregami_plugin.py  
FULLPATH\oregami\regname_plugin.py  
FULLPATH\oregami\typeregter_plugin.py  

Restart IDA, and the plugins should work.

Alternatively:  
Copy all files (including internal oregami folder, excluding setup.py) to the IDA plugins directory.  


## Use as script
Besides being used as plugins, oregami can be used also to write your own scripts!  

For this, you should first install using included setup.py file. Meaning that you should call:  
'python setup.py develop', and from then on you may use the internal classes and functions.  
Note that we recommend using 'develop' and not 'install', so that if you pull a new version of oregami, it will work out of the box.  

For example:  
-- script.py --  
```python
def find_func_usage(func_ea, reg='r0'):
    """
    Find and print all usages of a register, including the information of the specific operands
    it is in, and what operation it does in the operand.
    """
    import oregami
    rf = oregami.RegFrame(func_ea, reg)
    for insn in rf.get_instructions():
        print('Addr:{:x}'.format(insn.ea))
        for opnd in insn.operands:
            if opnd.uf_is_external:
                continue
            print('--opnd_idx:{} - {}'.format(opnd.n, oregami.UsageBits(opnd.op_flags)))
```            
    

## Scanning the usage frame
Let's assume the following sequence of opcodes:
```assembly
ROM:01000010                    e_lis     r10, 0x4004 # 0x40040000              # Load Immediate Shifted
ROM:01000014                    e_add16i  r10, r10, 0x1337 # 0x40041337         # Add Immediate
ROM:01000020                    se_mr     r30, r31                              # Move Register
ROM:01000022                    cmplw     r11, r10                              # Compare Logical Word
ROM:01000026                    se_bge    loc_1000036                           # Branch if greater than or equal
ROM:01000028
ROM:01000028    loc_1000028:                                                    # CODE XREF: sub_0100000+144↓j
ROM:01000028                    e_stmw    r30, 0(r11)                           # Store Multiple Word
ROM:0100002C                    e_add16i  r11, r11, 8                           # Add Immediate
ROM:01000030                    cmplw     r11, r10                              # Compare Logical Word
ROM:01000034                    se_blt    loc_1000028                           # Branch if less than
ROM:01000036
ROM:01000036    loc_1000036:                                                    # CODE XREF: sub_0100000+136↑j
ROM:01000036                    e_add16i r10, r10, 8                            # Add Immediate
ROM:0100003A                    e_li      r11, 0                                # Load Immediate
```

If we scan the usage frame of the r10 register, starting from the address 01000022, we will find three types of usages included in the usage frame.
### 1. Init
This will include the instructions which initialize the value of the register.  
We may want to include only the last instruction that changed the register value (address 01000014 in the example), or a sequence of operations used to set the initial value of the register (addresses 01000010 and 01000014 in the example).  
The sequence of operations used in the register initialization may be called an "init stage".  
You may choose to support an init stage, or not, depending on the parameter init_stage_bool in the RegFrame initialization.
### 2. Pure 
This will include the instructions which use the value of the register, and do not change it in any way. These correspond to lines 01000022 and 01000030 in the example.
### 3. Break
This will include the instructions which use the value of the register, but then change it's value. These instructions may be seen as included in two distinct usage frames - the one leading to them, and the one originating from them.  
This corresponds to line 01000036.
### 4. Out Break
When scanning the usage register, getting to an init operation, or a break operation will cause us to stop scanning in a certain direction.  
But, we may also stop the scan because of instructions outside the usage frame.
For example, scanning the usage frame of the r11 register starting from the address 01000030 will stop on line 0100003A.


## Classes and Functions
### RegFrame
This is the basic class used in oregami. By initializing it on an address and specific register, it will scan the usage frame of the register, and will create an UFIntruction for all the relevant instructions.  
get_instruction - get the instruction from the given address  
get_instructions - a generator, returning the instructions in the usage frame.  
  
You may also ask for specific subsets of the used instructions:  
get_init_instructions - get only instructions of the init type  
get_pure_instructions - get only instructions of the pure type  
get_break_instructions - get only instructions of the break type  
get_nobreak_instructions - get only instructions which are not of the break type (ie. init + pure)  
get_noinit_instructions - get only instructions which are not of the init type (ie. pure + break)  
get_outbreak_instructions - get only instructions of the out break type  
  
By default this class will cache the results of the scan, and prevent itself from rescanning the same usage frame.
This means that requesting the RegFrame of any instruction that was a part of the usage frame (specifically of the init + pure types. Not breaks, because starting a scan on them should return the usage frame originating from them) will return the same pre-calculated RegFrame instance.
In order to force a rescan, use the force flag when initializing the class.


### RFInstruction
This is the class returned by the RegFrame, representing an instruction in the usage frame.  
  
This class inherits from the sark Instruction class, and as such supports the same methods.  
One main difference is that instead of containing an operands array of sark Operand class, it will contain an array of UFOperand class.
  
This class also contains methods to understand the instruction type (init, pure, break, outbreak), and the operations bits (read, write, explicit, and different types of implicit)

### RFOperand
This is the class in the operands array inside a specific UFInstruction.  
  
This class inherits from the sark Instruction class, and as such supports the same methods.  
  
In additions to the sark operations, it contains methods to get the operation bits (read, write, explicit, and different types of implicit), and to know if the operand is actually part of the usage frame (useful to know which operand in a break type instruction is part of the usage frame)  

### RegInstruction
This is a class used to analyze a specific instruction, to know it's usage regarding registers.  
It does so using knowledge from IDA, textual analysis, and specific details specific to the processor.
The reason for this class, is that the basic IDA analysis tends to lie about the set of the registers used, the way they are used in many opcodes.
  
This class inherits from the sark Instruction class, and as such supports the same methods.  
One main difference is that instead of containing an operands array of sark Operand class, it will contain an array of RegOperand class.

### RegOperand
This is a class used to analyze a specific operand, to know it's usage regarding registers.  
It does so using knowledge from IDA, textual analysis, and specific details specific to the processor.
The reason for this class, is that the basic IDA analysis tends to lie about the set of the registers used, the way they are used in many opcodes.
  
This class inherits from the sark Operand class, and as such supports the same methods.
