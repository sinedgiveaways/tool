#!/usr/bin/env python3
"""Extract AMD64 MINIDUMP_EXCEPTION_STREAM, CONTEXT, stack and register memory."""
import struct, sys, shutil
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DMP=Path(sys.argv[1]); OUT=Path("orbitals_exception_analysis"); OUT.mkdir(exist_ok=True)
LEGACY_OUT=Path("caller_1B5A8FF0"); LEGACY_OUT.mkdir(exist_ok=True)
SIG=0x504D444D
def read(f,o,n):
    f.seek(o); b=f.read(n)
    if len(b)!=n: raise ValueError(f"short read at file offset {o:#x}")
    return b
def u32(f,o): return struct.unpack("<I",read(f,o,4))[0]
def u64(f,o): return struct.unpack("<Q",read(f,o,8))[0]
def streams(f,fs):
    if u32(f,0)!=SIG: raise ValueError("invalid MDMP signature")
    n,dr=u32(f,8),u32(f,12)
    if n>100000 or dr+n*12>fs: raise ValueError("bad stream directory")
    out={}
    for i in range(n):
        t,z,r=struct.unpack("<III",read(f,dr+i*12,12))
        if r<=fs and z<=fs-r: out[t]=(z,r)
    return out
def ranges(f,s,fs):
    out=[]
    if 9 in s:
        z,r=s[9]; n=u64(f,r); p=u64(f,r+8)
        if n>2000000 or 16+n*16>z: raise ValueError("bad Memory64List")
        for i in range(n):
            va,sz=struct.unpack("<QQ",read(f,r+16+i*16,16))
            if sz and p+sz<=fs: out.append((va,sz,p))
            p+=sz
    if 5 in s:
        z,r=s[5]; n=u32(f,r)
        if n<=2000000 and 4+n*16<=z:
            for i in range(n):
                va,sz,off=struct.unpack("<QII",read(f,r+4+i*16,16))
                if sz and off+sz<=fs: out.append((va,sz,off))
    return out
def readva(f,rs,va,n):
    # Read across adjacent minidump ranges instead of requiring one range to
    # cover the entire request.
    end=va+n; pos=va; chunks=[]
    while pos<end:
        candidates=[(start+sz,off+pos-start) for start,sz,off in rs if start<=pos<start+sz]
        if not candidates: return None
        range_end,file_off=max(candidates,key=lambda x:x[0])
        take=min(end-pos,range_end-pos)
        chunks.append(read(f,file_off,take))
        pos+=take
    return b"".join(chunks)
def scan_patterns(f,rs,specs,chunk_size=8*1024*1024,max_hits=200):
    """Search captured virtual-memory bytes for exact little-endian values."""
    hits={name:[] for name,_ in specs}
    seen={name:set() for name,_ in specs}
    total=0
    maxlen=max(len(pat) for _,pat in specs)
    for start,size,off in rs:
        pos=0
        carry=b""
        while pos<size:
            take=min(chunk_size,size-pos)
            chunk=read(f,off+pos,take)
            buf=carry+chunk
            buf_va=start+pos-len(carry)
            for name,pat in specs:
                idx=buf.find(pat)
                while idx>=0:
                    va=buf_va+idx
                    if start<=va and va+len(pat)<=start+size and va not in seen[name]:
                        seen[name].add(va)
                        if len(hits[name])<max_hits:
                            hits[name].append(va)
                    idx=buf.find(pat,idx+1)
            carry=buf[-(maxlen-1):] if maxlen>1 else b""
            pos+=take
            total+=take
    return total,hits
def memory_info(f,s):
    """Parse MINIDUMP_MEMORY_INFO_LIST (stream 16)."""
    if 16 not in s:return []
    z,r=s[16]
    if z<16:return []
    hs,es=struct.unpack("<II",read(f,r,8))
    n=u64(f,r+8)
    if hs<16 or es<48 or n>2000000 or hs+n*es>z:return []
    out=[]
    for i in range(n):
        p=r+hs+i*es
        base,alloc=struct.unpack("<QQ",read(f,p,16))
        aprot=u32(f,p+16); region=u64(f,p+24)
        state,protect,kind=struct.unpack("<III",read(f,p+32,12))
        out.append((base,alloc,region,aprot,state,protect,kind))
    return out
def modules(f,s):
    if 4 not in s:return []
    z,r=s[4]; n=u32(f,r); out=[]
    for i in range(n):
        m=r+4+i*108; base=u64(f,m); size=u32(f,m+8); nr=u32(f,m+20)
        ln=u32(f,nr); name=read(f,nr+4,ln).decode("utf-16le","replace").rstrip("\0")
        out.append((base,size,name))
    return out
def disasm(md,data,addr,limit=100):
    if not data:return ["<memory not captured>"]
    return [f"{i.address:016X}: {i.bytes.hex(' '):32s} {i.mnemonic:8s} {i.op_str}"
            for j,i in enumerate(md.disasm(data,addr)) if j<limit]
with DMP.open("rb") as f:
    fs=DMP.stat().st_size; s=streams(f,fs); rs=ranges(f,s,fs); mods=modules(f,s)
    lines=[f"dump={DMP.name}",f"file_size={fs}",f"streams={sorted(s)}",f"memory_ranges={len(rs)}"]
    for b,z,n in mods: lines.append(f"MODULE {b:#x}-{b+z:#x} {n}")
    if 6 not in s: raise SystemExit("ERROR: MINIDUMP_EXCEPTION_STREAM (type 6) absent")
    z,r=s[6]
    if z<168: raise SystemExit(f"ERROR: exception stream too short: {z}")
    tid=u32(f,r); code=u32(f,r+8); flags=u32(f,r+12); exaddr=u64(f,r+24); np=u32(f,r+32)
    info=[u64(f,r+40+i*8) for i in range(min(np,15))]
    # MINIDUMP_LOCATION_DESCRIPTOR is {DataSize, Rva}; RVA is at +164, not +160.
    ctxsize=u32(f,r+160); crva=u32(f,r+164)
    lines += ["",f"EXCEPTION thread_id={tid:#x} code={code:#010x} flags={flags:#x} address={exaddr:#x}",
              f"parameters({np})="+", ".join(hex(x) for x in info),
              f"context_size={ctxsize} context_rva={crva:#x}"]
    if not crva or ctxsize<256 or crva+ctxsize>fs: raise SystemExit("ERROR: invalid exception CONTEXT location")
    ctx=read(f,crva,ctxsize)
    names=["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi","r8","r9","r10","r11","r12","r13","r14","r15"]
    offsets=[120,128,136,144,152,160,168,176,184,192,200,208,216,224,232,240]
    regs={n:struct.unpack_from("<Q",ctx,o)[0] for n,o in zip(names,offsets)}
    regs["rip"]=struct.unpack_from("<Q",ctx,248)[0]
    lines.append("REGISTERS "+" ".join(f"{k}={v:#018x}" for k,v in regs.items()))
    md=Cs(CS_ARCH_X86,CS_MODE_64); md.detail=True
    rip=regs["rip"]
    lines += ["","FAULTING INSTRUCTIONS:"]+disasm(md,readva(f,rs,rip,128),rip)
    rsp=regs["rsp"]; stack=readva(f,rs,rsp,0x800)
    lines += ["","STACK @ RSP (first 0x800 bytes):"]
    if stack:
        for off in range(0,len(stack),16): lines.append(f"{rsp+off:016X}: "+stack[off:off+16].hex(" "))
    else: lines.append(f"<stack memory not captured at {rsp:#x}>")
    # The call's caller frame is below the current RSP; inspect it explicitly.
    pre_base=max(0,rsp-0x200)
    pre=readva(f,rs,pre_base,0x200)
    lines += ["","STACK BEFORE CURRENT RSP (0x200 bytes):"]
    if pre:
        for off in range(0,len(pre),16):
            lines.append(f"{pre_base+off:016X}: "+pre[off:off+16].hex(" "))
    else:
        lines.append("<preceding stack memory not captured>")
    candidate_base=max(0,rsp-0x78)
    candidate=readva(f,rs,candidate_base,0x200)
    lines += ["","CANDIDATE CALLER CONTEXT (RSP-0x78, 0x200 bytes; address is a hypothesis):"]
    if candidate:
        for off in range(0,len(candidate),16):
            lines.append(f"{candidate_base+off:016X}: "+candidate[off:off+16].hex(" "))
    else:
        lines.append("<candidate context not captured>")
    if stack:
        lines += ["","STACK RETURN-ADDRESS CANDIDATES:"]
        for off in range(0,len(stack)-7,8):
            q=struct.unpack_from("<Q",stack,off)[0]
            for mb,mz,mn in mods:
                if mb<=q<mb+mz:
                    lines.append(f"RSP+0x{off:03X} = {q:#018x} ({mn}+{q-mb:#x})")
                    break
    lines += ["","REGISTER-POINTED MEMORY (0x80 bytes where captured):"]
    for k,v in regs.items():
        if v:
            b=readva(f,rs,v,0x80)
            if b: lines.append(f"[{k}] {v:#x}: {b.hex(' ')}")
    lines += ["","MEMORY RANGE COVERAGE:"]
    for k in ("rcx","rdx","rsi"):
        v=regs[k]
        hit=next(((a,n) for a,n,_ in rs if a<=v<a+n),None)
        lines.append(f"{k}={v:#x}: "+(f"captured range [{hit[0]:#x},{hit[0]+hit[1]:#x}) remaining={hit[0]+hit[1]-v:#x}" if hit else "not present in minidump memory ranges"))
    desc=readva(f,rs,regs["rsi"],0x200)
    lines += ["","DESCRIPTOR / RSI QWORDS (0x000..0x1F8):"]
    if desc:
        for off in range(0,len(desc)-7,8):
            q=struct.unpack_from("<Q",desc,off)[0]
            lines.append(f"RSI+0x{off:03X} = {q:#018x}")
    else:
        lines.append("<0x200 bytes at RSI not fully captured in one memory range>")
    # Follow the four fields used by the caller's address calculation.
    lines += ["","CALLER INPUT FIELDS AND POINTED MEMORY:"]
    if desc:
        for off in (0xC8,0xD0,0xD8,0xE0):
            value=struct.unpack_from("<Q",desc,off)[0]
            hit=next(((a,n,fo) for a,n,fo in rs if a<=value<a+n),None)
            lines.append(f"RSI+0x{off:03X} = {value:#018x}")
            if hit:
                a,n,fo=hit
                lines.append(f"  mapped in dump range [{a:#x},{a+n:#x}), available={a+n-value:#x}")
                blob=readva(f,rs,value,min(0x100,a+n-value))
                if blob:
                    for j in range(0,len(blob),16):
                        lines.append(f"  {value+j:016X}: {blob[j:j+16].hex(' ')}")
            else:
                lines.append("  NOT CAPTURED as a direct virtual-memory range")
    lines += ["","DESCRIPTOR SOURCE BYTES AS 16-BIT WORDS:"]
    if desc:
        src=struct.unpack_from("<Q",desc,8)[0]
        lines.append("source qword = "+src.to_bytes(8,"little").hex(" "))
        lines.append("u16 words = "+", ".join(f"{x:#06x}" for x in struct.unpack("<4H",src.to_bytes(8,"little"))))
    # Reconstruct the selected 0x40-byte record from the live Cpu.x27 metadata.
    lines += ["","SOURCE/COUNT RECORD ADDRESS RECONSTRUCTION:"]
    if desc:
        x27=struct.unpack_from("<Q",desc,0xD8)[0]
        d0b=readva(f,rs,x27+0xD0,8)
        d8b=readva(f,rs,x27+0xD8,4)
        if d0b and d8b:
            ptr=struct.unpack("<Q",d0b)[0]
            index=struct.unpack("<i",d8b)[0]
            base=ptr if ptr else x27+0x10
            scaled=index<<6
            record_base=(base+scaled-0x40)&0xFFFFFFFFFFFFFFFF
            source_field=record_base+0x30
            count_field=record_base+0x38
            lines += [f"x27={x27:#x} x27[+0xD0]={ptr:#x} x27[+0xD8]={index}",
                      f"base={base:#x} index_times_0x40={scaled:#x}",
                      f"selected_record_base={record_base:#x}",
                      f"source_field(+0x30)={source_field:#x}",
                      f"count_field(+0x38)={count_field:#x}"]
            neighborhood_start=max(0,record_base-0x100)
            neighborhood=readva(f,rs,neighborhood_start,0x300)
            if neighborhood:
                (OUT/"selected_record_neighborhood.bin").write_bytes(neighborhood)
                for off in range(0,len(neighborhood),16):
                    lines.append(f"  {neighborhood_start+off:016X}: {neighborhood[off:off+16].hex(' ')}")
            else:
                lines.append("<0x300-byte record/object neighborhood not fully captured>")
            rec=readva(f,rs,record_base,0x40)
            if rec:
                for off in range(0,0x40,16):
                    lines.append(f"  {record_base+off:016X}: {rec[off:off+16].hex(' ')}")
            else:
                lines.append("<selected record bytes not captured as one contiguous range>")
            sb=readva(f,rs,source_field,8)
            cb=readva(f,rs,count_field,8)
            lines.append("source_field_now="+(hex(struct.unpack("<Q",sb)[0]) if sb else "<not captured>"))
            if cb:
                q=struct.unpack("<Q",cb)[0]
                lines.append(f"count_field_qword_now={q:#x} low_dword={q&0xFFFFFFFF:#x}")
            else:
                lines.append("count_field_now=<not captured>")
            mi=memory_info(f,s)
            for label,addr in (("x27",x27),("record_base",record_base),("source_field",source_field),("count_field",count_field)):
                matches=[m for m in mi if m[0]<=addr<m[0]+m[2]]
                if matches:
                    for base0,alloc0,size0,ap0,state0,prot0,kind0 in matches[:3]:
                        lines.append(f"{label} memory_region: base={base0:#x} allocation_base={alloc0:#x} size={size0:#x} state={state0:#x} protect={prot0:#x} type={kind0:#x}")
                else:
                    lines.append(f"{label} memory_region: no captured MemoryInfoList entry for {addr:#x}")
        else:
            lines.append("could not read x27+0xD0/+0xD8 from captured memory")
    # Correlate the destination with the dump's virtual-memory region metadata.
    meminfo=memory_info(f,s)
    lines += ["","DESTINATION MEMORY-INFO REGIONS:"]
    dest=struct.unpack_from("<Q",desc,0)[0] if desc else 0x12E1A8000C
    region_hits=[m for m in meminfo if m[0]<=dest<m[0]+m[2]]
    if region_hits:
        for base,alloc,region,aprot,state,protect,kind in region_hits:
            lines.append(f"base={base:#x} allocation_base={alloc:#x} region_size={region:#x} allocation_protect={aprot:#x} state={state:#x} protect={protect:#x} type={kind:#x}")
    else:
        lines.append(f"no MemoryInfoList region contains destination {dest:#x}; entries={len(meminfo)}")
    # Search all captured memory for the exact bad source and size inputs.
    source_value=struct.unpack_from("<Q",desc,8)[0] if desc else 0x01460149013D0140
    specs=[
        ("source_qword",struct.pack("<Q",source_value)),
        ("x25_qword",struct.pack("<Q",0x01490140)),
        ("x25_dword",struct.pack("<I",0x01490140)),
        ("copy_size_qword",struct.pack("<Q",0x05240500)),
        ("copy_size_dword",struct.pack("<I",0x05240500)),
    ]
    scanned,hits=scan_patterns(f,rs,specs)
    scan_lines=[f"scanned_virtual_bytes={scanned:#x} ({scanned/1024/1024/1024:.2f} GiB)"]
    for name,_ in specs:
        scan_lines.append(f"\n{name}: {len(hits[name])} hit(s)"+(" (first 200 shown)" if len(hits[name])>=200 else ""))
        for va in hits[name]:
            scan_lines.append(f"  {va:#018x}")
            around=readva(f,rs,max(0,va-0x20),0x60)
            if around:
                scan_lines.append("    "+around.hex(" "))
    (OUT/"bad_argument_value_occurrences.txt").write_text("\n".join(scan_lines),encoding="utf-8")
    lines += ["","BAD ARGUMENT VALUE SCAN:"]+scan_lines
    # Inspect the exact native helper and thunk identified in the stack.
    exe=next(((b,z,n) for b,z,n in mods if n.lower().endswith("orbitals-recomp.exe")),None)
    lines += ["","NATIVE HELPER / THUNK DISASSEMBLY:"]
    if exe:
        base,imagesz,exename=exe
        lines.append(f"EXE {exename} imagebase={base:#x} size={imagesz:#x}")
        for label,rva in (("helper_40CE0",0x40CE0),("thunk_70C430",0x70C430)):
            va=base+rva
            lines.append(f"\n{label} RVA={rva:#x} VA={va:#x}")
            lo=max(base,va-0x60); hi=min(base+imagesz,va+0x180)
            blob=readva(f,rs,lo,hi-lo)
            lines += disasm(md,blob,lo,100)
    else:
        lines.append("orbitals-recomp.exe module not found")
    # Disassemble the exact guest caller region containing the wrapper call
    # and the suspected (2-index)*0x38 calculation.
    game=next(((b,z,n) for b,z,n in mods if n.lower().endswith("orbitalgame.dll")),None)
    lines += ["","GUEST CALLER WINDOWS:"]
    if game:
        gbase,gsize,gname=game
        lines.append(f"GAME {gname} imagebase={gbase:#x} size={gsize:#x}")
        for label,lo_rva,hi_rva in (("caller_full_function",0x1B5A7000,0x1B5A9600),):
            va=gbase+lo_rva; size=hi_rva-lo_rva
            lines.append(f"\n{label} RVA=[{lo_rva:#x},{hi_rva:#x}) VA={va:#x}")
            blob=readva(f,rs,va,size)
            lines += disasm(md,blob,va,1000)
    # Write dedicated, complete disassembly files so long listings are not
    # truncated in the Actions console.
    if game:
        gbase,gsize,gname=game
        caller_lo=gbase+0x1B5A7000
        caller_len=0x2600
        caller_blob=readva(f,rs,caller_lo,caller_len)
        (OUT/"guest_caller_1B5A7000.txt").write_text(
            "\n".join([f"module={gname}",f"base={gbase:#x}",f"window={caller_lo:#x}+{caller_len:#x}"]+disasm(md,caller_blob,caller_lo,2000)),
            encoding="utf-8")
        wrapper_va=gbase+0x1C11DF00
        wrapper_lo=gbase+0x1C11DEF0
        wrapper_len=0x500
        wrapper_blob=readva(f,rs,wrapper_lo,wrapper_len)
        (OUT/"guest_memcpy_wrapper_1C11DF00.txt").write_text(
            "\n".join([f"module={gname}",f"imagebase={gbase:#x}",f"wrapper_va={wrapper_va:#x}",f"window={wrapper_lo:#x}+{wrapper_len:#x}"]+disasm(md,wrapper_blob,wrapper_lo,2000)),
            encoding="utf-8")
    # Inspect the helper's optional large-copy tracking callback target.
    if exe:
        base,imagesz,exename=exe
        va=base+0x4AFCD0
        lines += ["","LARGE-COPY TRACKER CALLBACK TARGET:",f"VA={va:#x} RVA=0x4AFCD0"]
        lo=va; blob=readva(f,rs,lo,0x300)
        tracker_lines=[f"EXE {exename} imagebase={base:#x}",f"tracker_rva=0x4AFCD0 va={va:#x}"]
        tracker_lines += disasm(md,blob,lo,300)
        (OUT/"native_large_copy_tracker_4AFCD0.txt").write_text("\n".join(tracker_lines),encoding="utf-8")
        lines += disasm(md,blob,lo,180)
    # Include the UCRT prologue, not only the faulting basic block, to recover
    # its stack-frame size and map saved helper registers accurately.
    ucrt_lo=max(0,rip-0x300)
    ucrt_blob=readva(f,rs,ucrt_lo,0x500)
    ucrt_lines=[f"ucrt_rip={rip:#x}",f"window={ucrt_lo:#x}+0x500"]+disasm(md,ucrt_blob,ucrt_lo,1200)
    (OUT/"ucrt_memmove_prologue_and_fault.txt").write_text("\n".join(ucrt_lines),encoding="utf-8")
    lines += ["","DISASSEMBLY AROUND RIP:"]+disasm(md,readva(f,rs,max(0,rip-0x40),0x200),max(0,rip-0x40),100)
    (OUT/"exception_context.txt").write_text("\n".join(lines),encoding="utf-8")
    # Old workflow revisions upload caller_1B5A8FF0/; mirror output there too
    # so a rerun of an older failed job can still publish the new analysis.
    for p in OUT.iterdir():
        if p.is_file(): shutil.copy2(p, LEGACY_OUT/p.name)
    print("\n".join(lines[-180:]))
