# FileRecovery Tool

## Overview
FileRecovery is a Python-based tool designed to recover specific file types from a disk image. It was developed using Python 3.8 and provides a straightforward way to extract and recover files such as MPG, PDF, GIF, JPG, DOCX, AVI, and PNG.

## Features
Supported File Types: MPG, PDF, GIF, JPG, DOCX, AVI, PNG
Disk Image Input: Accepts disk images in `.dd` format
Output:
  - Recovered files stored in the working directory
  - Generic file names
  - Hexadecimal starting and ending offsets within the disk image
  - SHA-256 hash for each recovered file

## Requirements
Python Version: Python 3.8 or higher

## Output
The tool will output the following for each recovered file:
- **Recovered Files**: Files will be placed in the current working directory.
- **Generic File Name**: Files will be named generically, based on their order of recovery.
- **Hex Offsets**: The hexadecimal starting and ending offsets of each file within the disk image.
- **SHA-256 Hash**: The SHA-256 hash value for each recovered file.



After running the program, the recovered files will be stored in the working directory with their corresponding details.
