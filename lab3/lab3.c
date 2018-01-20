#include "stdio.h"
#include "stdlib.h"

typedef unsigned char uint8;
typedef unsigned int uint32;
typedef unsigned short int uint16;

#define CR0_PE  0x1
#define CR0_PG  (1 << 31)
#define CR4_PSE (1 << 4)
#define PF_EXCEPTION 14

#define PTE_WU_4KB  0x007  //present write user 4Kb
#define PDE_WU_PT   0x007  //present write user PT

#pragma pack (push, 1)
typedef union _PTE {
    uint32 raw;
    struct {
        uint32 p:1;
        uint32 rw:1;
        uint32 us:1;
        uint32 xx:4; // PCD, PWT, A, D
        uint32 pat:1;
        uint32 g:1;
        uint32 ign:3;
        uint32 pfn:20;
    };
} PTE, *PPTE;

typedef union _PDE {
    uint32 raw;
    struct {
        uint32 p:1;
        uint32 rw:1;
        uint32 us:1;
        uint32 xx:4; // PCD, PWT, A, Ign
        uint32 pat:1;
        uint32 ign:4;
        uint32 pta:20;
    };
} PDE, *PPDE;

typedef struct _IDTENTRY {
    uint16 offset_l;
    uint16 seg_sel;
    uint8  zero;
    uint8  flags;
    uint16 offset_h;
} IDTENTRY, *PIDTENTRY;

typedef struct _DTR {
    uint16 limit;
    uint32 base;
    uint16 _padding;
} DTR, *PDTR;

typedef union _SELECTOR {
    uint16 raw;
    struct {
        uint16 pl:2;
        uint16 table:1;
        uint16 index:13;
    };
} SELECTOR, *PSELECTOR;

typedef struct _SYSINFO {
    SELECTOR cs;
    uint32 cr0;
    DTR gdt;
    DTR idt;
    SELECTOR ldt;
    SELECTOR tr;
} SYSINFO, *PSYSINFO;

void get_sysinfo(PSYSINFO psysinfo)
{
    uint16 _cs = 0;
    uint32 _cr0 = 0;
    uint16 _ldt = 0;
    uint16 _tr = 0;
    DTR* _gdt = &psysinfo->gdt;
    DTR* _idt = &psysinfo->idt;

    __asm {
        mov eax, cr0
        mov _cr0, eax
        mov ax, cs
        mov _cs, ax

        mov eax, _gdt
        sgdt [eax]
        mov eax, _idt
        sidt [eax]
        sldt _ldt
        str _tr
    }
    
    psysinfo->cr0 = _cr0;
    psysinfo->cs.raw = _cs;
    psysinfo->ldt.raw = _ldt;
    psysinfo->tr.raw = _tr;
}

PPDE Pdir;
uint32 Test_pte;
uint32 Test_addr;

void idt_set_gate(PIDTENTRY idt, uint8 num, uint32 offset, uint16 seg_sel, uint8 flags) {
    idt[num].offset_l = offset & 0xFFFF;
    idt[num].offset_h = (offset >> 16) & 0xFFFF;
    idt[num].seg_sel = seg_sel;
    idt[num].zero = 0;
    idt[num].flags = flags;
}

uint32 Test_res = 0;

void __declspec(naked) pf_handler(void) 
{
    __asm {
        push eax
        push edx

        mov edx, cr2
        cmp edx, Test_addr      // check if fault addr is test addr
        jne pf

        mov eax, Test_pte       // PTE corresponding to test address
        or dword ptr[eax], 1h   // restore P bit
        invlpg [eax]            // invalidate all paging caches for test address
        
        lea eax, Test_res
        mov [eax], 1
        
        jmp done
    pf:
        pop edx
        pop eax
        push old_segment
        push old_offset
        retf 
    done:
        pop edx
        pop eax
        add esp, 4
        iretd
    }
}

/*
 * Creates 1024 PTs with trivial mapping, 
 * returns pointer to first PTE of first PT
 */
PPTE create_pts()
{
    uint32 pte_i;
    uint32 pts_size = 4 * 1024 * 1024; // 4MB
    uint32 pt_size = 4 * 1024; // 4KB
    void* p = malloc(pts_size + pt_size);
    uint32 _p = (uint32)p;
    uint32 _p_aligned = (_p & ~(pt_size - 1)) + pt_size;
    PPTE pt = (PPTE)_p_aligned;
    
    printf("Allocated 4100KB: 0x%08X - 0x%08X, 4MB aligned: 0x%08X - 0x%08X\n", 
            _p, _p + pts_size + pt_size, _p_aligned, _p_aligned + pts_size);
    
    for (pte_i = 0; pte_i < 1024 * 1024; pte_i++) {
        pt[pte_i].raw = pte_i * 0x1000;
        pt[pte_i].raw |= PTE_WU_4KB;
        if ((pte_i == 0) || (pte_i == 1) || (pte_i == 1024 * 1024 - 1))
            printf("PTE = 0x%08X at %p\n", pt[pte_i].raw, pt + pte_i);
        if (pte_i == 2)
            printf("...\n");
    }

    return pt;
}

/*
 * Creates PD with trivial mapping, 
 * returns pointer to first PDE
 */
PPDE create_pd()
{
    uint32 pde_i;
    PPTE pts = create_pts();
    uint32 pd_size = 4 * 1024; // 4KB
    void *p = malloc(2 * pd_size);
    uint32 _p = (uint32)p;
    uint32 _p_aligned = (_p & ~(pd_size - 1)) + pd_size;
    PPDE pd = (PPDE)_p_aligned;

    printf("Allocated 8KB: 0x%08X - 0x%08X, 4KB aligned: 0x%08X - 0x%08X\n", 
            _p, _p + 2 * pd_size, _p_aligned, _p_aligned + pd_size);

    for (pde_i = 0; pde_i < 1024; pde_i++) {
        pd[pde_i].raw = (uint32)pts + pde_i * 0x1000;
        pd[pde_i].raw |= PDE_WU_PT;
        if ((pde_i == 0) || (pde_i == 1) || (pde_i == 1023))
            printf("PDE = 0x%08X at %p\n", pd[pde_i].raw, pd + pde_i);
        if (pde_i == 2)
            printf("...\n");
    }

    return pd;
}

void set_pf_handler(PSYSINFO sysinfo)
{
    PIDTENTRY idt_table = (PIDTENTRY)sysinfo->idt.base;
    uint32 old_offset = idt_table[PF_EXCEPTION].offset_h << 16 | idt_table[PF_EXCEPTION].offset_l;
    uint16 old_segment = idt_table[PF_EXCEPTION].seg_sel;
    uint32 new_offset = 0;
    uint16 new_segment = 0;
    
    __asm {
        mov edx, offset pf_handler
        mov new_offset, edx
        mov ax, seg pf_handler
        mov new_segment, ax
    }

    idt_set_gate(idt_table, PF_EXCEPTION, new_offset, new_segment, idt_table[PF_EXCEPTION].flags);
}

void paging_test(int death_test)
{
    uint32 p_size = 4096;
    void *p = malloc(2 * p_size);
    uint32 _p = (uint32)p;
    PPTE test_pte;
    SYSINFO sysinfo;
    
    _p = (_p & ~(p_size - 1)) + p_size;
    test_pte = ((PPTE)(Pdir[(_p & 0xFFC00000) >> 22].pta << 12)) + ((_p & 0x003FF000) >> 12);

    printf("Test page at 0x%08X, corresponding PTE at %p\n", _p, test_pte);

    (*test_pte).p = 0;

    get_sysinfo(&sysinfo);
    set_pf_handler(&sysinfo);

    Test_pte = (uint32)test_pte;
    Test_addr = (uint32)_p;

    *((char *)_p) = 0x55; // Our PF handler will be called
    printf("Test result: %s\n", Test_res ? "PASSED!" : "FAILED");
   	
	if (death_test) {
    	(*test_pte).p = 0;
    	
    	printf("Default handler:\n");
    	printf("I am memory %d\n", *((uint32 *)(_p + 4)));
	}
}

void paging_on()
{
    uint32 _pd;
    
    Pdir = create_pd();
    _pd = (uint32)Pdir;
 
    __asm {
        pushfd
        mov eax, _pd
        mov cr3, eax        // this also resets instruction cache

        mov eax, cr4
        or  eax, 0x00000080 // enable CR4.PGE
        and eax, 0xFFFFFFEF // disable CR4.PSE
        mov cr4, eax

        mov eax, cr0
        or  eax, 0x80000000
        mov cr0, eax        // enable CR0.PG

        popfd
    }
}

void main()
{
    SYSINFO si;

    get_sysinfo(&si);
    printf("CR0 = 0x%08X : PG = %d\n", si.cr0, si.cr0 & CR0_PG ? 1 : 0);

    paging_on();
    
    get_sysinfo(&si);
    printf("CR0 = 0x%08X : PG = %d\n", si.cr0, si.cr0 & CR0_PG ? 1 : 0);

    paging_test(1);
}
