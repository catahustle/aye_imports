## aye-imports
simple import wrapper
contains 2 wrapper types:
- redirect import call
- inline xor

# How redirecting calls works
- allocate RWX memory with size of 0x1000 (doesn't matter how much you will allocate, just make sure it will be enough)
- instead of usual place function address in IMAGE_THUNK_DATA::Function, it replaces this pointer to allocated memory
- this memory is filled with
```asm
mov eax, xored_function_address
xor eax, xor_key
jmp eax
```
so when your program attempts to call import, it won't call the function directly

# How inline xor-ing works
- instead of direct call it will replace call instruction with
```asm
mov eax, hashed_function_name
xor eax, xor_key
call eax
```
- using Hacker Disassembler Engine it disassembles all instructions in order to find hashed_function_name and patch it