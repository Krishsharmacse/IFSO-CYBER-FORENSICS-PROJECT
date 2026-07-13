import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

def dump_all_functions():
    args = getScriptArgs()
    if len(args) < 1:
        print("Missing output file argument.")
        return

    output_filename = args[0]
    program = currentProgram
    print("Starting decompilation for: {}".format(program.getName()))
    
    decompInterface = DecompInterface()
    decompInterface.openProgram(program)
    monitor = ConsoleTaskMonitor()
    
    with open(output_filename, "w") as out_file:
        fm = program.getFunctionManager()
        functions = fm.getFunctions(True)
        
        for func in functions:
            # Skip external/thunk functions (imported DLL functions have no local code)
            if func.isExternal() or func.isThunk():
                continue
            
            # Decompile the function with a 60-second timeout per function
            res = decompInterface.decompileFunction(func, 60, monitor)
            
            if res and res.getDecompiledFunction():
                c_code = res.getDecompiledFunction().getC()
                out_file.write(c_code)
                out_file.write("\n\n")
            else:
                out_file.write("/* Failed to decompile {} */\n\n".format(func.getName()))
                
    print("Decompilation complete. Saved to: {}".format(output_filename))

if __name__ == "__main__":
    dump_all_functions()
