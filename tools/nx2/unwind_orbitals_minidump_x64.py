#!/usr/bin/env python3
"""Unwind the real AMD64 call stack from an existing Windows minidump.

Reads the ExceptionStream context and applies the loaded modules' PE .pdata/.xdata
RUNTIME_FUNCTION records. It deliberately does not treat arbitrary code-looking
qwords on the stack as active return addresses.
"""
import argparse
import bisect
import mmap
import struct
from pathlib import Path

REGS = ("rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
        "r8","r9","r10","r11","r12","r13","r14","r15")
REG_BY_INDEX = dict(enumerate(REGS))
EXCEPTION_STREAM = 6
MODULE_LIST = 4
MEMORY_LIST = 5
MEMORY64_LIST = 9

class Minidump:
    def __init__(self, path):
        self.path = Path(path)
        self.file = self.path.open("rb")
        self.mm = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        b = self.mm
        if b[:4] != b"MDMP":
            raise ValueError("Not an MDMP file")
        nstreams, directory = struct.unpack_from("<II", b, 8)
        self.streams = {}
        for i in range(nstreams):
            typ, size, rva = struct.unpack_from("<III", b, directory + 12*i)
            self.streams.setdefault(typ, (rva, size))
        self.modules = self._modules()
        self.ranges = self._ranges()
        self.starts = [x[0] for x in self.ranges]
        self.pe_tables = {}

    def close(self):
        self.mm.close()
        self.file.close()

    def _modules(self):
        out=[]
        if MODULE_LIST not in self.streams:
            return out
        at,size=self.streams[MODULE_LIST]
        count=struct.unpack_from("<I",self.mm,at)[0]
        for i in range(count):
            o=at+4+108*i
            base, image_size, _, _, name_rva=struct.unpack_from("<QIIII",self.mm,o)
            n=struct.unpack_from("<I",self.mm,name_rva)[0]
            name=self.mm[name_rva+4:name_rva+4+n].decode("utf-16-le","replace")
            out.append({"base":base,"size":image_size,"name":name.replace("\\","/").split("/")[-1]})
        return out

    def _ranges(self):
        out=[]
        if MEMORY64_LIST in self.streams:
            at,size=self.streams[MEMORY64_LIST]
            count,filepos=struct.unpack_from("<QQ",self.mm,at)
            for i in range(count):
                va,n=struct.unpack_from("<QQ",self.mm,at+16+16*i)
                if n and filepos+n <= len(self.mm):
                    out.append((va,n,filepos))
                filepos += n
        if MEMORY_LIST in self.streams:
            at,size=self.streams[MEMORY_LIST]
            count=struct.unpack_from("<I",self.mm,at)[0]
            for i in range(count):
                va,n,rva=struct.unpack_from("<QII",self.mm,at+4+16*i)
                if n and rva+n <= len(self.mm):
                    out.append((va,n,rva))
        return sorted(out,key=lambda x:x[0])

    def read(self, va, n):
        if va < 0 or n < 0:
            return None
        out=bytearray()
        pos=va
        end=va+n
        while pos<end:
            i=bisect.bisect_right(self.starts,pos)-1
            if i<0:
                return None
            start,length,filepos=self.ranges[i]
            if not start <= pos < start+length:
                return None
            take=min(end,start+length)-pos
            out += self.mm[filepos+pos-start:filepos+pos-start+take]
            pos += take
        return bytes(out)

    def module_of(self, va):
        for m in self.modules:
            if m["base"] <= va < m["base"]+m["size"]:
                return m["name"], va-m["base"]
        return None

    def exception_context(self):
        if EXCEPTION_STREAM not in self.streams:
            raise ValueError("ExceptionStream absent")
        at,size=self.streams[EXCEPTION_STREAM]
        tid=struct.unpack_from("<I",self.mm,at)[0]
        code,flags,nested,address,nparams=struct.unpack_from("<IIQQI",self.mm,at+8)
        params=list(struct.unpack_from("<15Q",self.mm,at+40))[:min(nparams,15)]
        ctx_size,ctx_rva=struct.unpack_from("<II",self.mm,at+160)
        if not ctx_size or not ctx_rva:
            raise ValueError("ExceptionStream has no context")
        c=self.mm[ctx_rva:ctx_rva+ctx_size]
        if len(c)<0x100:
            raise ValueError("AMD64 context too short")
        regs=dict(zip(REGS,struct.unpack_from("<16Q",c,0x78)))
        regs["rip"]=struct.unpack_from("<Q",c,0xf8)[0]
        return tid,code,address,params,regs

    def runtime_functions(self, module):
        key=module["base"]
        if key in self.pe_tables:
            return self.pe_tables[key]
        base=module["base"]
        dos=self.read(base,0x40)
        if not dos or dos[:2]!=b"MZ":
            self.pe_tables[key]=[]
            return []
        peoff=struct.unpack_from("<I",dos,0x3c)[0]
        nt=self.read(base+peoff,24)
        if not nt or nt[:4]!=b"PE\0\0":
            self.pe_tables[key]=[]
            return []
        machine,nsections,ts,ptrsym,nsym,optsize,chars=struct.unpack_from("<HHIIIHH",nt,4)
        opt=self.read(base+peoff+24,optsize)
        if not opt or len(opt)<144 or struct.unpack_from("<H",opt,0)[0]!=0x20b:
            self.pe_tables[key]=[]
            return []
        exception_rva,exception_size=struct.unpack_from("<II",opt,112+3*8)
        if not exception_rva or exception_size<12 or exception_size%12:
            self.pe_tables[key]=[]
            return []
        raw=self.read(base+exception_rva,exception_size)
        if not raw:
            self.pe_tables[key]=[]
            return []
        funcs=[]
        for i in range(exception_size//12):
            begin,end,unwind=struct.unpack_from("<III",raw,i*12)
            if begin<end and end<=module["size"]:
                funcs.append((begin,end,unwind))
        funcs.sort()
        self.pe_tables[key]=funcs
        return funcs

    def find_function(self, module, rva):
        funcs=self.runtime_functions(module)
        if not funcs:
            return None
        begins=[x[0] for x in funcs]
        i=bisect.bisect_right(begins,rva)-1
        if i>=0 and funcs[i][0] <= rva < funcs[i][1]:
            return funcs[i]
        return None

def qword(d, va):
    b=d.read(va,8)
    return struct.unpack("<Q",b)[0] if b else None

def unwind_info(d, module, rf, regs, rip):
    begin,end,unwind_rva=rf
    ui=d.read(module["base"]+unwind_rva,4)
    if not ui:
        raise ValueError("UNWIND_INFO header not captured")
    version=ui[0]&7
    flags=ui[0]>>3
    prolog=ui[1]
    count=ui[2]
    frame_reg=ui[3]&0xf
    frame_off=(ui[3]>>4)*16
    codes_raw=d.read(module["base"]+unwind_rva+4,count*2)
    if codes_raw is None:
        raise ValueError("UNWIND_CODE array not captured")
    codes=[]
    i=0
    while i<count:
        codeoff=codes_raw[i*2]
        opbyte=codes_raw[i*2+1]
        op=opbyte&0xf
        info=opbyte>>4
        extra=0
        operand=None
        if op==1: # UWOP_ALLOC_LARGE
            if info==0:
                extra=1
                operand=struct.unpack_from("<H",codes_raw,(i+1)*2)[0]*8
            elif info==1:
                extra=2
                operand=struct.unpack_from("<I",codes_raw,(i+1)*2)[0]
        elif op in (4,8): # SAVE_NONVOL / SAVE_XMM128
            extra=1
            operand=struct.unpack_from("<H",codes_raw,(i+1)*2)[0]*(8 if op==4 else 16)
        elif op in (5,9): # FAR variants
            extra=2
            operand=struct.unpack_from("<I",codes_raw,(i+1)*2)[0]
        codes.append((codeoff,op,info,operand))
        i += 1+extra
    if i>count:
        raise ValueError("UNWIND_CODE slot count overflow")
    return {"version":version,"flags":flags,"prolog":prolog,"frame_reg":frame_reg,
            "frame_off":frame_off,"codes":codes,"unwind_rva":unwind_rva,"count":count}

def apply_unwind(d, module, rf, regs):
    begin,end,unwind_rva=rf
    ui=unwind_info(d,module,rf,regs,regs["rip"])
    # Codes are stored in descending prologue-offset order: undo in that order.
    rip_rva=regs["rip"]-module["base"]
    in_prolog=(rip_rva-begin)<ui["prolog"]
    max_codeoff=rip_rva-begin if in_prolog else 0x10000
    ops=[]
    for codeoff,op,info,operand in ui["codes"]:
        if codeoff>max_codeoff:
            continue
        rsp=regs["rsp"]
        if op==0: # UWOP_PUSH_NONVOL
            name=REG_BY_INDEX.get(info)
            value=qword(d,rsp)
            if name is None or value is None: raise ValueError("PUSH_NONVOL stack slot missing")
            regs[name]=value
            regs["rsp"]=rsp+8
            ops.append(f"PUSH_NONVOL {name}")
        elif op==1: # UWOP_ALLOC_LARGE
            if operand is None: raise ValueError("bad ALLOC_LARGE")
            regs["rsp"]=rsp+operand
            ops.append(f"ALLOC_LARGE +{operand:#x}")
        elif op==2: # UWOP_ALLOC_SMALL
            size=info*8+8
            regs["rsp"]=rsp+size
            ops.append(f"ALLOC_SMALL +{size:#x}")
        elif op==3: # UWOP_SET_FPREG
            name=REG_BY_INDEX.get(ui["frame_reg"])
            if name is None: raise ValueError("bad frame register")
            regs["rsp"]=regs[name]-ui["frame_off"]
            ops.append(f"SET_FPREG {name}-{ui['frame_off']:#x}")
        elif op==4: # UWOP_SAVE_NONVOL
            name=REG_BY_INDEX.get(info)
            value=qword(d,rsp+operand)
            if name is None or value is None: raise ValueError("SAVE_NONVOL slot missing")
            regs[name]=value
            ops.append(f"SAVE_NONVOL {name} at rsp+{operand:#x}")
        elif op==5: # UWOP_SAVE_NONVOL_FAR
            name=REG_BY_INDEX.get(info)
            value=qword(d,rsp+operand)
            if name is None or value is None: raise ValueError("SAVE_NONVOL_FAR slot missing")
            regs[name]=value
            ops.append(f"SAVE_NONVOL_FAR {name} at rsp+{operand:#x}")
        elif op in (6,7):
            ops.append(f"UNSUPPORTED/EPILOG op={op} info={info}")
            raise ValueError(f"unsupported unwind op {op}")
        elif op==8: # UWOP_SAVE_XMM128, ignore vector register contents
            ops.append(f"SAVE_XMM128 xmm{info} at rsp+{operand:#x}")
        elif op==9:
            ops.append(f"SAVE_XMM128_FAR xmm{info} at rsp+{operand:#x}")
        elif op==10: # UWOP_PUSH_MACHFRAME
            err=8 if info else 0
            newrip=qword(d,rsp+err)
            newrsp=qword(d,rsp+err+24)
            if newrip is None or newrsp is None: raise ValueError("machine frame missing")
            regs["rip"]=newrip
            regs["rsp"]=newrsp
            ops.append(f"PUSH_MACHFRAME error_code={bool(info)}")
            return ui,ops,True
        else:
            raise ValueError(f"unknown unwind op {op}")
    # Chained runtime function info follows the even-aligned unwind-code array.
    if ui["flags"] & 4:
        off=module["base"]+unwind_rva+4+((ui["count"]+1)&~1)*2
        raw=d.read(off,12)
        if not raw: raise ValueError("CHAININFO runtime function missing")
        chained=struct.unpack("<III",raw)
        ui2,ops2,mach=apply_unwind(d,module,chained,regs)
        ops += ["CHAININFO"]+ops2
        if mach: return ui,ops,True
    return ui,ops,False

def call_instruction(d, module_info, ret):
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        md=Cs(CS_ARCH_X86,CS_MODE_64)
        code=d.read(ret-16,16)
        if not code: return ""
        candidates=[]
        for off in range(16):
            ins=list(md.disasm(code[off:],ret-16+off))
            if ins and ins[-1].address+ins[-1].size==ret:
                last=ins[-1]
                if last.mnemonic.startswith("call"):
                    candidates.append(last)
        if candidates:
            ins=candidates[-1]
            mod=d.module_of(ins.address)
            where=f"{mod[0]}+{mod[1]:#x}" if mod else f"{ins.address:#x}"
            return f"{where}: {ins.mnemonic} {ins.op_str}"
    except Exception:
        pass
    return ""

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("dump")
    ap.add_argument("--depth",type=int,default=24)
    ap.add_argument("--out")
    a=ap.parse_args()
    d=Minidump(a.dump)
    lines=[]
    def p(s=""): lines.append(str(s))
    try:
        tid,code,exc_addr,params,regs=d.exception_context()
        m=d.module_of(exc_addr)
        p(f"DUMP={d.path.name} size={d.path.stat().st_size:,}")
        p(f"THREAD={tid:#x} EXCEPTION={code:#010x} ADDRESS={exc_addr:#018x}")
        p(f"EXCEPTION_MODULE={m[0]+'+'+hex(m[1]) if m else 'unknown'}")
        if code==0xC0000005 and len(params)>=2:
            p(f"ACCESS={'READ' if params[0]==0 else 'WRITE' if params[0]==1 else 'EXECUTE' if params[0]==8 else params[0]} TARGET={params[1]:#018x}")
        p(f"MODULES={len(d.modules)} MEMORY_RANGES={len(d.ranges)}")
        seen=set()
        for frame in range(a.depth):
            rip=regs["rip"]; rsp=regs["rsp"]
            mod=d.module_of(rip)
            if mod:
                module=next(x for x in d.modules if x["name"]==mod[0] and x["base"]<=rip<x["base"]+x["size"])
                label=f"{mod[0]}+{mod[1]:#x}"
            else:
                module=None; label=f"{rip:#018x}"
            p("")
            p(f"FRAME {frame:02d}: RIP={rip:#018x} {label} RSP={rsp:#018x} RBP={regs['rbp']:#018x}")
            p("  NONVOL: "+" ".join(f"{r.upper()}={regs[r]:#018x}" for r in ("rbx","rbp","rsi","rdi","r12","r13","r14","r15")))
            if frame and mod:
                ci=call_instruction(d,module,rip)
                if ci: p("  CALLSITE: "+ci)
            if (rip,rsp) in seen:
                p("  STOP: repeated frame")
                break
            seen.add((rip,rsp))
            if rsp < 0x10000 or rsp >= 0x800000000000:
                p("  STOP: non-user RSP")
                break
            if module:
                rf=d.find_function(module,rip-module["base"])
            else:
                rf=None
            try:
                if rf:
                    ui,ops,mach=apply_unwind(d,module,rf,regs)
                    p(f"  UNWIND: pdata [{rf[0]:#x},{rf[1]:#x}) info={rf[2]:#x} version={ui['version']} flags={ui['flags']:#x}")
                    p("  OPS: "+(", ".join(ops) if ops else "none"))
                    if mach:
                        continue
                else:
                    p("  UNWIND: leaf/no pdata entry; pop return address")
                ret=qword(d,regs["rsp"])
                if ret is None:
                    p("  STOP: return-address stack slot not captured")
                    break
                regs["rip"]=ret
                regs["rsp"]+=8
                if ret==0 or ret>=0x800000000000:
                    p(f"  STOP: invalid return address {ret:#x}")
                    break
            except Exception as e:
                p(f"  STOP: unwind error: {e}")
                break
        result="\n".join(lines)+"\n"
        if a.out: Path(a.out).write_text(result,encoding="utf-8")
        print(result,end="")
    finally:
        d.close()

if __name__=="__main__":
    main()
