import ctypes
from ctypes import c_uint, c_char_p, c_bool
import argparse
import sys, os
import tkinter as tk

os.add_dll_directory("C:/msys64/mingw64/bin")
LIB_NAME = "AES_g++.so"
dll_path = os.path.abspath(LIB_NAME)
try:
    lib = ctypes.CDLL(dll_path, mode=3)
    print(f"[INFO] Library loaded: {dll_path}")
except Exception as e:
    print(f"[ERROR] Failed to load library: {e}")
    sys.exit(1)
    
functions = [
    "GetKeyIVSize",       
    "generateKeyIV",      
    "saveKeyIVToFile",     
    "loadKeyIVFromFile",   
    "LoadDataFromFile",    
    "SaveDataToFile",      
    "AESEncrypt",          
    "AESDecrypt",          
    "parseMode",
    "parseOperation"
]


for func in functions:
    try:
        getattr(lib, func)
        print(f"[INFO] Function {func} loaded successfully.")
    except Exception as e:
        print(f"[ERROR] Failed to load function {func}: {e}")
        sys.exit(1)
        
