# AES_GUI_keyfile_no_check.py
# Modified Tkinter GUI for AES encryption/decryption using a C++ shared library.
# Key/IV management is file-based (Generate/Save and Load).
# Key file loading now loads the entire file without size validation, assuming 16-byte key.

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import ctypes
from ctypes import c_int, c_size_t, c_char_p, c_bool, POINTER, byref, create_string_buffer
import os
import binascii

# --- Constants ---
os.add_dll_directory("C:/msys64/mingw64/bin")
AES_MODES = ["ECB", "CBC", "OFB", "CFB", "CTR", "XTS", "CCM", "GCM"]
KEY_SIZES = [16, 24, 32] # In bytes (128, 192, 256 bits)
DEFAULT_MODE = "CBC"
DEFAULT_KEY_SIZE = 16
LIB_NAME = "AES_g++.so" # Assuming the library is in the same directory
LIB_PATH = os.path.join(os.path.dirname(__file__), LIB_NAME)
AES_BLOCKSIZE = 16
ASSUMED_LOAD_KEY_SIZE = 16

# --- C Library Loading and Function Definitions ---

# Define ModeType enum values (must match C++ enum)
class ModeType(c_int):
    ECB = 0
    CBC = 1
    OFB = 2
    CFB = 3
    CTR = 4
    XTS = 5
    CCM = 6
    GCM = 7
    UNKNOWN = 8

try:
    # Use the library name provided by the user
    lib_path = os.path.abspath(LIB_NAME)
    lib = ctypes.CDLL(lib_path)
    print(f"[INFO] Library loaded: {lib_path}")
except OSError as e:
    messagebox.showerror("Library Load Error", f"Failed to load shared library \n{lib_path}\n\n{e}\n\nPlease ensure the library file exists and is compatible.")
    exit(1)

# Define function prototypes
try:
    # ModeType parseMode(const char *modeStr);
    lib.parseMode.argtypes = [c_char_p]
    lib.parseMode.restype = ModeType

    # bool generateKeyIV(ModeType mode, size_t baseKeySize, byte* keyBuffer, size_t keyBufSize, byte* ivBuffer, size_t ivBufSize, size_t* actualKeySize, size_t* actualIvSize);
    lib.generateKeyIV.argtypes = [ModeType, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, POINTER(c_size_t), POINTER(c_size_t)]
    lib.generateKeyIV.restype = c_bool

    # bool AESEncrypt(ModeType mode, const byte *key, size_t keyLen, const byte *iv, size_t ivLen, const byte *plaintext, size_t plaintextLen, byte *ciphertextBuffer, size_t *ciphertextLen);
    lib.AESEncrypt.argtypes = [ModeType, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, POINTER(c_size_t)]
    lib.AESEncrypt.restype = c_bool

    # bool AESDecrypt(ModeType mode, const byte *key, size_t keyLen, const byte *iv, size_t ivLen, const byte *ciphertext, size_t ciphertextLen, byte *recoveredPlaintextBuffer, size_t *recoveredPlaintextLen);
    lib.AESDecrypt.argtypes = [ModeType, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, c_size_t, c_char_p, POINTER(c_size_t)]
    lib.AESDecrypt.restype = c_bool

    print("[INFO] C function prototypes defined successfully.")

except AttributeError as e:
    messagebox.showerror("Function Load Error", f"Failed to find a required function in the library.\n\n{e}\n\nPlease ensure the C++ code was compiled correctly with exports.")
    exit(1)

# --- Python Helper Function (Replicates C++ GetKeyIVSize logic - Used for Generation Only) ---
def get_expected_key_iv_size(mode_enum, base_key_size):
    """Calculates the expected actual key and IV sizes based on mode and base key size."""
    key_size = base_key_size
    iv_size = AES_BLOCKSIZE

    if mode_enum == ModeType.ECB:
        iv_size = 0
    elif mode_enum == ModeType.XTS:
        if base_key_size == 16: key_size = 32
        elif base_key_size == 24: key_size = 48
        elif base_key_size == 32: key_size = 64
        else: return None # Invalid base size for XTS
        iv_size = AES_BLOCKSIZE
    elif mode_enum == ModeType.CCM:
        iv_size = 12
    elif mode_enum == ModeType.GCM:
        iv_size = 12
    elif mode_enum in [ModeType.CBC, ModeType.OFB, ModeType.CFB, ModeType.CTR]:
        iv_size = AES_BLOCKSIZE
    else: # UNKNOWN mode
        return None

    # Final check for non-XTS modes
    if mode_enum != ModeType.XTS and base_key_size not in [16, 24, 32]:
        return None

    return key_size, iv_size

# --- GUI Application Class ---
class AesGuiApp:
    def __init__(self, master):
        self.master = master
        master.title("AES Encryption/Decryption Tool (Key File - No Check)")
        master.geometry("700x600")

        # --- Internal State ---
        self.loaded_key = None
        self.loaded_iv = None
        self.loaded_key_size = 0
        self.loaded_iv_size = 0

        # --- Variables ---
        self.mode_var = tk.StringVar(value=DEFAULT_MODE)
        self.keysize_var = tk.IntVar(value=DEFAULT_KEY_SIZE) # Used only for generation
        self.key_file_var = tk.StringVar(value="No key file loaded")
        self.input_type_var = tk.StringVar(value="manual") # "manual" or "file"
        self.input_file_var = tk.StringVar()
        self.output_file_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")

        # --- Style ---
        style = ttk.Style()
        style.configure("TLabel", padding=5)
        style.configure("TButton", padding=5)
        style.configure("TEntry", padding=5)
        style.configure("TCombobox", padding=5)
        style.configure("TRadiobutton", padding=5)

        # --- Layout ---
        main_frame = ttk.Frame(master, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Configuration Frame
        config_frame = ttk.LabelFrame(main_frame, text="Configuration", padding="10")
        config_frame.pack(fill=tk.X, pady=5)
        config_frame.columnconfigure(1, weight=1)
        config_frame.columnconfigure(3, weight=1)

        ttk.Label(config_frame, text="Mode:").grid(row=0, column=0, sticky=tk.W)
        mode_combo = ttk.Combobox(config_frame, textvariable=self.mode_var, values=AES_MODES, state="readonly")
        mode_combo.grid(row=0, column=1, sticky=tk.EW, padx=5)

        ttk.Label(config_frame, text="Key Size (for Gen):").grid(row=0, column=2, sticky=tk.W, padx=(10, 0))
        keysize_combo = ttk.Combobox(config_frame, textvariable=self.keysize_var, values=KEY_SIZES, state="readonly", width=5)
        keysize_combo.grid(row=0, column=3, sticky=tk.W, padx=5)

        # Key File Frame
        key_file_frame = ttk.LabelFrame(main_frame, text="Key/IV File Management", padding="10")
        key_file_frame.pack(fill=tk.X, pady=5)
        key_file_frame.columnconfigure(1, weight=1)

        ttk.Label(key_file_frame, text="Current Key File:").grid(row=0, column=0, sticky=tk.W)
        key_file_display = ttk.Label(key_file_frame, textvariable=self.key_file_var, relief=tk.SUNKEN, padding=2, anchor=tk.W)
        key_file_display.grid(row=0, column=1, columnspan=2, sticky=tk.EW, padx=5)

        key_button_frame = ttk.Frame(key_file_frame)
        key_button_frame.grid(row=1, column=0, columnspan=3, pady=(5,0))
        ttk.Button(key_button_frame, text="Generate & Save Key File...", command=self.generate_and_save_key_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_button_frame, text="Load Key File...", command=self.load_key_file).pack(side=tk.LEFT, padx=5)

        # Input Frame
        input_frame = ttk.LabelFrame(main_frame, text="Input Data", padding="10")
        input_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        input_frame.columnconfigure(0, weight=1)
        input_frame.rowconfigure(2, weight=1)

        input_radio_frame = ttk.Frame(input_frame)
        input_radio_frame.grid(row=0, column=0, sticky=tk.W, pady=(0,5))
        ttk.Radiobutton(input_radio_frame, text="Manual Input (UTF-8)", variable=self.input_type_var, value="manual", command=self.toggle_input_mode).pack(side=tk.LEFT)
        ttk.Radiobutton(input_radio_frame, text="File Input", variable=self.input_type_var, value="file", command=self.toggle_input_mode).pack(side=tk.LEFT, padx=10)

        self.input_file_frame = ttk.Frame(input_frame)
        self.input_file_frame.grid(row=1, column=0, sticky=tk.EW)
        ttk.Button(self.input_file_frame, text="Browse Input File...", command=self.browse_input_file).pack(side=tk.LEFT)
        self.input_file_label = ttk.Label(self.input_file_frame, textvariable=self.input_file_var, relief=tk.SUNKEN, padding=2)
        self.input_file_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        self.input_text = scrolledtext.ScrolledText(input_frame, wrap=tk.WORD, height=8, borderwidth=1, relief=tk.SUNKEN)
        self.input_text.grid(row=2, column=0, sticky=tk.NSEW, pady=(5,0))

        # Output Frame
        output_frame = ttk.LabelFrame(main_frame, text="Output Data", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        output_frame.columnconfigure(0, weight=1)
        output_frame.rowconfigure(1, weight=1)

        output_file_frame = ttk.Frame(output_frame)
        output_file_frame.grid(row=0, column=0, sticky=tk.EW)
        ttk.Button(output_file_frame, text="Save Output To File...", command=self.browse_output_file).pack(side=tk.LEFT)
        self.output_file_label = ttk.Label(output_file_frame, textvariable=self.output_file_var, relief=tk.SUNKEN, padding=2)
        self.output_file_label.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        self.output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, height=8, state=tk.DISABLED, borderwidth=1, relief=tk.SUNKEN)
        self.output_text.grid(row=1, column=0, sticky=tk.NSEW, pady=(5,0))

        # Action Frame
        action_frame = ttk.Frame(main_frame, padding="5")
        action_frame.pack(fill=tk.X)
        ttk.Button(action_frame, text="Encrypt", command=self.encrypt_data).pack(side=tk.LEFT, padx=10, pady=5)
        ttk.Button(action_frame, text="Decrypt", command=self.decrypt_data).pack(side=tk.LEFT, padx=10, pady=5)

        # Status Bar
        status_bar = ttk.Label(master, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W, padding=2)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        # Initial UI state
        self.toggle_input_mode() # Hide file widgets initially

    # --- GUI Callbacks ---
    def update_status(self, message):
        self.status_var.set(message)
        self.master.update_idletasks()

    def toggle_input_mode(self):
        if self.input_type_var.get() == "manual":
            self.input_text.config(state=tk.NORMAL)
            self.input_file_frame.grid_remove()
        else:
            self.input_text.delete("1.0", tk.END)
            self.input_text.config(state=tk.DISABLED)
            self.input_file_frame.grid()

    def browse_input_file(self):
        filename = filedialog.askopenfilename(title="Select Input File")
        if filename:
            self.input_file_var.set(filename)
            self.update_status(f"Input file selected: {os.path.basename(filename)}")

    def browse_output_file(self):
        filename = filedialog.asksaveasfilename(title="Save Output To File")
        if filename:
            self.output_file_var.set(filename)
            self.update_status(f"Output file selected: {os.path.basename(filename)}")

    def generate_and_save_key_file(self):
        self.update_status("Generating Key/IV...")
        try:
            mode_str = self.mode_var.get().encode("utf-8")
            base_key_size = c_size_t(self.keysize_var.get())
            c_mode = lib.parseMode(mode_str)

            if c_mode == ModeType.UNKNOWN:
                messagebox.showerror("Error", f"Invalid mode selected: {self.mode_var.get()}")
                self.update_status("Error: Invalid mode")
                return

            # Determine buffer sizes needed
            key_buf = create_string_buffer(64) # Max possible key size (XTS-256)
            iv_buf = create_string_buffer(16)  # Max possible IV/Nonce size
            actual_key_size = c_size_t(0)
            actual_iv_size = c_size_t(0)

            success = lib.generateKeyIV(
                c_mode, base_key_size,
                key_buf, c_size_t(len(key_buf.raw)),
                iv_buf, c_size_t(len(iv_buf.raw)),
                byref(actual_key_size), byref(actual_iv_size)
            )

            if not success:
                expected_sizes = get_expected_key_iv_size(c_mode, self.keysize_var.get())
                if expected_sizes is None:
                     messagebox.showerror("Generation Error", f"Invalid base key size ({self.keysize_var.get()} bytes) for mode {self.mode_var.get()}.")
                else:
                    messagebox.showerror("Generation Error", "Failed to generate Key/IV in C++ library (unknown reason).")
                self.update_status("Error: Key/IV generation failed")
                return

            key_bytes = key_buf.raw[:actual_key_size.value]
            iv_bytes = iv_buf.raw[:actual_iv_size.value]

            # Ask user where to save
            save_path = filedialog.asksaveasfilename(
                title="Save Generated Key/IV File",
                defaultextension=".key",
                filetypes=[("Key Files", "*.key"), ("Binary Files", "*.bin"), ("All Files", "*.*")])

            if not save_path:
                self.update_status("Key/IV generation cancelled.")
                return

            # Write key and IV to file
            with open(save_path, "wb") as f:
                f.write(key_bytes)
                if actual_iv_size.value > 0:
                    f.write(iv_bytes)

            # Load the newly saved key/IV into the app state
            self.loaded_key = key_bytes
            self.loaded_iv = iv_bytes
            self.loaded_key_size = actual_key_size.value
            self.loaded_iv_size = actual_iv_size.value
            self.key_file_var.set(os.path.basename(save_path))
            self.update_status(f"Key/IV generated and saved to {os.path.basename(save_path)}")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during Key/IV generation/saving: {e}")
            self.update_status("Error generating/saving Key/IV")

    def load_key_file(self):
        self.update_status("Loading Key/IV file...")
        try:
            load_path = filedialog.askopenfilename(
                title="Load Key/IV File",
                filetypes=[("Key Files", "*.key"), ("Binary Files", "*.bin"), ("All Files", "*.*")])

            if not load_path:
                self.update_status("Key/IV file loading cancelled.")
                return

            # Read the entire file
            with open(load_path, "rb") as f:
                file_content = f.read()
            file_size = len(file_content)

            if file_size == 0:
                messagebox.showerror("Load Error", "Selected key file is empty.")
                self.update_status("Error: Key file empty")
                return

            # --- MODIFIED Logic: Load without size check, assume 16-byte key --- 
            key_data = None
            iv_data = None
            key_size = 0
            iv_size = 0

            if file_size >= ASSUMED_LOAD_KEY_SIZE:
                key_size = ASSUMED_LOAD_KEY_SIZE
                key_data = file_content[:key_size]
                iv_data = file_content[key_size:]
                iv_size = len(iv_data)
            else:
                # If file is smaller than assumed key size, treat whole file as key
                key_size = file_size
                key_data = file_content
                iv_data = b''
                iv_size = 0
                messagebox.showwarning("Load Warning", f"File size ({file_size} bytes) is less than the assumed key size ({ASSUMED_LOAD_KEY_SIZE} bytes). Treating entire file as key.")

            # Load into app state
            self.loaded_key = key_data
            self.loaded_iv = iv_data
            self.loaded_key_size = key_size
            self.loaded_iv_size = iv_size
            self.key_file_var.set(os.path.basename(load_path))
            self.update_status(f"Key/IV loaded from {os.path.basename(load_path)} (ASSUMED {key_size}-byte key)")
            messagebox.showinfo("Load Info", f"Loaded {file_size} bytes from file.\nAssumed Key Size: {key_size} bytes\nAssumed IV/Nonce Size: {iv_size} bytes\n\nWARNING: Ensure this matches the requirements for the selected mode ({self.mode_var.get()}) for correct operation.")

        except Exception as e:
            messagebox.showerror("Error", f"An error occurred during Key/IV file loading: {e}")
            self.update_status("Error loading Key/IV file")
            self.loaded_key = None # Reset state on error
            self.loaded_iv = None
            self.key_file_var.set("No key file loaded")

    def get_input_data(self):
        """Gets input data as bytes based on selected mode."""
        if self.input_type_var.get() == "manual":
            text_input = self.input_text.get("1.0", tk.END).strip()
            if not text_input:
                return None
            try:
                return text_input.encode("utf-8")
            except UnicodeEncodeError:
                 messagebox.showerror("Encoding Error", "Manual input contains characters that cannot be encoded to UTF-8.")
                 return None
        else: # file input
            filepath = self.input_file_var.get()
            if not filepath or not os.path.exists(filepath):
                messagebox.showerror("File Error", "Please select a valid input file.")
                return None
            try:
                with open(filepath, "rb") as f:
                    return f.read()
            except Exception as e:
                messagebox.showerror("File Read Error", f"Failed to read input file: {e}")
                return None

    def display_output_data(self, data_bytes):
        """Displays output data, attempting UTF-8 decode, falling back to hex."""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete("1.0", tk.END)
        try:
            # Try decoding as UTF-8 first
            decoded_text = data_bytes.decode("utf-8")
            self.output_text.insert(tk.END, decoded_text)
            self.update_status("Operation successful. Output displayed as UTF-8 text.")
        except UnicodeDecodeError:
            # If decode fails, display as hex
            hex_output = binascii.hexlify(data_bytes).decode("ascii")
            self.output_text.insert(tk.END, hex_output)
            self.update_status("Operation successful. Output displayed as Hex (non-UTF8 data).")
        except Exception as e:
             self.output_text.insert(tk.END, f"Error displaying output: {e}")
             self.update_status("Operation successful, but error displaying output.")
        finally:
            self.output_text.config(state=tk.DISABLED)

    def save_output_data(self, data_bytes):
        """Saves the output bytes to the selected file."""
        filepath = self.output_file_var.get()
        if not filepath:
            # Only display, don't force save
            return
        try:
            with open(filepath, "wb") as f:
                f.write(data_bytes)
            self.update_status(f"Output saved to {os.path.basename(filepath)}")
        except Exception as e:
            messagebox.showerror("File Write Error", f"Failed to save output file: {e}")
            self.update_status("Error saving output file")

    def _perform_operation(self, operation_func):
        self.update_status("Processing...")
        try:
            # Check if Key/IV are loaded
            if self.loaded_key is None:
                messagebox.showerror("Key Error", "No Key/IV file loaded. Please load or generate a key file first.")
                self.update_status("Error: Key/IV not loaded")
                return

            # Get Mode
            mode_str = self.mode_var.get().encode("utf-8")
            c_mode = lib.parseMode(mode_str)
            if c_mode == ModeType.UNKNOWN:
                messagebox.showerror("Error", f"Invalid mode selected: {self.mode_var.get()}")
                self.update_status("Error: Invalid mode")
                return

            # Get Input Data
            input_data = self.get_input_data()
            if input_data is None:
                self.update_status("Error: No valid input data")
                return # Error already shown

            # Prepare C arguments using loaded key/iv (with assumed sizes)
            c_key = c_char_p(self.loaded_key)
            c_key_len = c_size_t(self.loaded_key_size)
            c_iv = c_char_p(self.loaded_iv) if self.loaded_iv_size > 0 else None
            c_iv_len = c_size_t(self.loaded_iv_size)
            c_input = c_char_p(input_data)
            c_input_len = c_size_t(len(input_data))

            # Estimate output buffer size
            estimated_output_len = len(input_data) + 16 + 16 + 64 # Ample margin
            output_buffer = create_string_buffer(estimated_output_len)
            c_output_len = c_size_t(estimated_output_len)

            # Call C function
            success = operation_func(
                c_mode, c_key, c_key_len, c_iv, c_iv_len,
                c_input, c_input_len,
                output_buffer, byref(c_output_len)
            )

            # Handle potential buffer too small error
            if not success and c_output_len.value > estimated_output_len:
                self.update_status("Reallocating output buffer...")
                new_size = c_output_len.value
                output_buffer = create_string_buffer(new_size)
                c_output_len = c_size_t(new_size)
                success = operation_func(
                    c_mode, c_key, c_key_len, c_iv, c_iv_len,
                    c_input, c_input_len,
                    output_buffer, byref(c_output_len)
                )

            # Process result
            if success:
                output_bytes = output_buffer.raw[:c_output_len.value]
                self.display_output_data(output_bytes)
                self.save_output_data(output_bytes)
            else:
                op_name = "Encryption" if operation_func == lib.AESEncrypt else "Decryption"
                error_detail = f"Check mode ({self.mode_var.get()}), key file integrity, and input data. Ensure the loaded key/IV sizes ({self.loaded_key_size}/{self.loaded_iv_size} bytes) are correct for this mode."
                if c_mode in [ModeType.CCM, ModeType.GCM] and operation_func == lib.AESDecrypt:
                    error_detail += " (Decryption failure often indicates authentication error / data tampering)."
                messagebox.showerror(f"{op_name} Error", f"{op_name} failed in C++ library. {error_detail}")
                self.update_status(f"Error: {op_name} failed")
                self.output_text.config(state=tk.NORMAL)
                self.output_text.delete("1.0", tk.END)
                self.output_text.config(state=tk.DISABLED)

        except Exception as e:
            messagebox.showerror("Error", f"An unexpected error occurred: {e}")
            self.update_status("Error: Unexpected exception")

    def encrypt_data(self):
        self._perform_operation(lib.AESEncrypt)

    def decrypt_data(self):
        self._perform_operation(lib.AESDecrypt)

# --- Main Execution ---
if __name__ == "__main__":
    root = tk.Tk()
    app = AesGuiApp(root)
    root.mainloop()

