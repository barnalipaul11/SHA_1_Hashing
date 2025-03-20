import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox

def compute_sha1(file_path):
    sha1 = hashlib.sha1()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                sha1.update(chunk)
        return sha1.hexdigest()
    except Exception as e:
        messagebox.showerror("Error", f"Failed to read file: {e}")
        return None

def browse_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        hash_result = compute_sha1(file_path)
        if hash_result:
            result_var.set(hash_result)

def copy_to_clipboard():
    root.clipboard_clear()
    root.clipboard_append(result_var.get())
    root.update()
    messagebox.showinfo("Copied", "SHA-1 hash copied to clipboard")

# GUI setup
root = tk.Tk()
root.title("SHA-1 File Hasher")
root.geometry("500x200")

frame = tk.Frame(root)
frame.pack(pady=20)

browse_button = tk.Button(frame, text="Select File", command=browse_file)
browse_button.pack()

result_var = tk.StringVar()
result_label = tk.Label(root, textvariable=result_var, wraplength=480, fg="blue")
result_label.pack(pady=10)

copy_button = tk.Button(root, text="Copy Hash", command=copy_to_clipboard)
copy_button.pack()

root.mainloop()
