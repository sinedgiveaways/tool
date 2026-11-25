#!/usr/bin/env python3
"""Extract AMD64 MINIDUMP_EXCEPTION_STREAM, CONTEXT, stack and register memory."""
import struct, sys
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64

DMP=Path(sys.argv[1]); OUT=Path("orbitals_exception_analysis"); OUT.mkdir(exist_ok=True)
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
        for label,lo_rva,hi_rva in (("caller_index_and_memcpy",0x1B5A8E00,0x1B5A9500),):
            va=gbase+lo_rva; size=hi_rva-lo_rva
            lines.append(f"\n{label} RVA=[{lo_rva:#x},{hi_rva:#x}) VA={va:#x}")
            blob=readva(f,rs,va,size)
            lines += disasm(md,blob,va,1000)
    # Write dedicated, complete disassembly files so long listings are not
    # truncated in the Actions console.
    if game:
        gbase,gsize,gname=game
        caller_lo=gbase+0x1B5A8E00
        caller_len=0x700
        caller_blob=readva(f,rs,caller_lo,caller_len)
        (OUT/"guest_caller_1B5A8E00.txt").write_text(
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
        lines += disasm(md,blob,lo,180)
    lines += ["","DISASSEMBLY AROUND RIP:"]+disasm(md,readva(f,rs,max(0,rip-0x40),0x200),max(0,rip-0x40),100)
    (OUT/"exception_context.txt").write_text("\n".join(lines),encoding="utf-8")
    print("\n".join(lines[-180:]))
