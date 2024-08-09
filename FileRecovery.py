#!/usr/bin/env python3

import re
import struct
import binascii
import hashlib
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

signatures = [
    ['.mpg', b'\x00\x00\x01\xB3.\x00', b'\x00\x00\x00\x01\xB7'],
    ['.mpg', b'\x00\x00\x01\xBA.\x00', b'\x00\x00\x00\x01\xB9'],
    ['.pdf', b'\x25\x50\x44\x46', b'\x0A\x25\x25\x45\x4F\x46\x0A'],
    ['.pdf', b'\x25\x50\x44\x46', b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A'],
    ['.pdf', b'\x25\x50\x44\x46', b'\x0A\x25\x25\x45\x4F\x46\x0A'],
    ['.pdf', b'\x25\x50\x44\x46', b'\x0A\x25\x25\x45\x4F\x46'],
    ['.pdf', b'\x25\x50\x44\x46', b'\x0D\x25\x25\x45\x4F\x46\x0D'],
    ['.bmp', b'\x42\x4D....\x00\x00\x00\x00', None],
    ['.gif', b'\x47\x49\x46\x38\x37\x61', b'\x00\x00\x3B'],
    ['.gif', b'\x47\x49\x46\x38\x39\x61', b'\x00\x00\x3B'],
    ['.jpg', b'\xFF\xD8\xFF\xE0', b'\xFF\xD9'],
    ['.jpg', b'\xFF\xD8\xFF\xE1', b'\xFF\xD9'],
    ['.jpg', b'\xFF\xD8\xFF\xE2', b'\xFF\xD9'],
    ['.jpg', b'\xFF\xD8\xFF\xE8', b'\xFF\xD9'],
    ['.jpg', b'\xFF\xD8\xFF\xDB', b'\xFF\xD9'],
    ['.docx', b'\x50\x4B\x03\x04\x14\x00\x06\x00', b'\x50\x4B\x05\x06'],
    ['.avi', b'\x52\x49\x46\x46....\x41\x56\x49\x20\x4C\x49\x53\x54', None],
    ['.png', b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', b'\x49\x45\x4E\x44\xAE\x42\x60\x82']
]

BUF_SIZE = 65536

def sha256_hash(file):
    with open(file, "rb") as hashfile:
        data = hashfile.read(BUF_SIZE)
        hasher = hashlib.sha256(data)
        while data:
            data = hashfile.read(BUF_SIZE)
            hasher.update(data)
    return hasher.hexdigest()

def recover_files(file_name, output_text):
    headers = []
    footers = []
    count = 1
    try:
        with open(file_name, "rb") as file:
            b = file.read()

        head_skip = False
        foot_skip = False
        pdf_skip = False

        for sig in signatures:
            reg_head = re.compile(sig[1])
            for match_head in reg_head.finditer(b):
                offset = match_head.start()
                head_skip = False
                if offset in headers:
                    continue

                start = b[offset:]
                next_offset = 0
                if sig[0] == '.pdf' and head_skip is False:
                    for match in reg_head.finditer(b[offset + 1:]):
                        next_offset = match.start() + offset
                        break

                if head_skip is False:
                    if sig[2] is not None:
                        reg_foot = re.compile(sig[2])
                        for match_foot in reg_foot.finditer(start):
                            end = match_foot.end()
                            end += offset
                            pdf_skip = False
                            next_end = 0
                            if sig[0] == '.pdf':
                                for match in reg_foot.finditer(b[end:]):
                                    next_end = match.start() + end
                                    break
                                if next_offset != 0:
                                    if end > next_offset:
                                        pdf_skip = True
                                        break
                                    elif next_end != 0:
                                        if next_end > next_offset:
                                            break
                            elif sig[0] == '.docx':
                                end += 18
                                break
                            else:
                                break
                    else:
                        if sig[0] == '.bmp':
                            head = 2
                        elif sig[0] == '.avi':
                            head = 4
                        size_start = offset + head
                        size = str(hex(b[size_start])[2:].zfill(2)) + str(hex(b[size_start + 1])[2:].zfill(2)) + str(
                            hex(b[size_start + 2])[2:].zfill(2)) + str(hex(b[size_start + 3])[2:].zfill(2))
                        size_b = binascii.unhexlify(size)
                        long_size = struct.unpack('<l', size_b)
                        end = offset + long_size[0]
                        if sig[0] == '.avi':
                            end += 8

                foot_skip = False
                if end in footers:
                    foot_skip = True

                if not (head_skip or foot_skip or pdf_skip):
                    headers.append(offset)
                    footers.append(end)
                    newfile = b[offset:end]
                    name = 'file' + str(count) + sig[0]
                    with open(name, "wb") as file_out:
                        file_out.write(newfile)

                    file_hash = sha256_hash(name)
                    count += 1
                    output_text.insert(tk.END, f"\nFile Name: {name}\n")
                    output_text.insert(tk.END, f"Starting Offset: {hex(offset)}\n")
                    output_text.insert(tk.END, f"End Offset: {hex(end)}\n")
                    output_text.insert(tk.END, f"SHA-256 Hash: {file_hash}\n")
                    output_text.see(tk.END)
                    output_text.update()

        messagebox.showinfo("Success", "File recovery complete!")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")

def select_file():
    file_path = filedialog.askopenfilename(title="Select Disk Image")
    if file_path:
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

def start_recovery():
    file_name = file_entry.get()
    if not file_name:
        messagebox.showwarning("Input Required", "Please select a disk image file.")
        return
    output_text.delete(1.0, tk.END)
    recover_files(file_name, output_text)

root = tk.Tk()
root.title("File Recovery Tool")

frame = tk.Frame(root)
frame.pack(padx=10, pady=10)

file_entry = tk.Entry(frame, width=50)
file_entry.grid(row=0, column=0, padx=5, pady=5)

browse_button = tk.Button(frame, text="Browse", command=select_file)
browse_button.grid(row=0, column=1, padx=5, pady=5)

recover_button = tk.Button(frame, text="Recover Files", command=start_recovery)
recover_button.grid(row=1, column=0, columnspan=2, pady=10)

output_text = scrolledtext.ScrolledText(root, width=70, height=20)
output_text.pack(padx=10, pady=10)

root.mainloop()
