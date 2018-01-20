#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

typedef unsigned char uint8;
typedef unsigned short int uint16;
typedef unsigned int uint32;

#define CR0_PE 0x1
#define CR0_PG (1<<31) //0x80000000

#define BASE_FROM_DESCRIPTOR(x) ((x->desc.base_low) | (x->desc.base_mid << 16) | (x->desc.base_high << 24))
#define LIMIT_FROM_DESCRIPTOR(x) (((x->desc.limit_low) | (x->desc.limit_high << 16)) << (x->desc.g ? 12 : 0))

#pragma pack (push, 1)
typedef struct _DTR {
    uint16 limit;
    uint32 base;
    uint16 _padding;
} DTR, *PDTR;

typedef union _GATE {
    struct {
        uint32 low;
        uint32 high;
    } raw;
    struct {
        uint16 reserved1;
        uint16 tss;
        uint8 reserved2;
        uint8 magic:5;
        uint8 dpl:2;
        uint8 p:1;
        uint16 reserved3;
    } task;
    struct {
        uint16 offset_low;
        uint16 segm_sel;
        uint8 reserved1:5;
        uint8 magic1:3;
        uint8 magic2:3;
        uint8 d:1;
        uint8 magic3:1;
        uint8 dpl:2;
        uint8 p:1;
        uint16 offset_high;
    } int_or_trap;
} GATE, *PGATE;

typedef union _DESC {
    struct {
        uint32 low;
        uint32 high;
    } raw;
    struct {
        uint16 limit_low;
        uint16 base_low;
        uint8 base_mid;
        uint8 type:4;
        uint8 s:1;
        uint8 dpl:2;
        uint8 p:1;
        uint8 limit_high:4;
        uint8 avl:1;
        uint8 l:1;
        uint8 db:1;
        uint8 g:1;
        uint8 base_high;
    } desc;
} DESC, *PDESC;

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

typedef struct _TSS {
    uint16 ptl;
    uint16 reserved;

    uint32 esp0;
    uint16 ss0;
    uint16 reserved1;

    uint32 esp1;
    uint16 ss1;
    uint16 reserved2;

    uint32 esp2;
    uint16 ss2;
    uint16 reserved3;

    uint32 tssCR3;
    uint32 tssEIP;
    uint32 tssEFLAGS;
    uint32 tssEAX;

    uint32 tssECX;
    uint32 tssEDX;
    uint32 tssEBX;
    uint32 tssESP;

    uint32 tssEBP;
    uint32 tssESI;
    uint32 tssEDI;

    uint16 tssES;
    uint16 reserved4;
    uint16 tssCS;
    uint16 reserved5;
    uint16 tssSS;
    uint16 reserved6;
    uint16 tssDS;
    uint16 reserved7;
    uint16 tssFS;
    uint16 reserved8;
    uint16 tssGS;
    uint16 reserved9;

    uint16 ldtss;
    uint16 reserved10;
    uint8 debug;
    uint8 reserved11;
    uint16 iomapbaseaddr;         
} TSS, *PTSS;

void get_sysinfo(SYSINFO* psysinfo)
{
    uint16 _cs = 0;
    uint32 _cr0 = 0;
    DTR* _gdt = &psysinfo->gdt;
    DTR* _idt = &psysinfo->idt;
    uint16 _ldt = 0;
    uint16 _tr = 0;

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

        //xor ax, ax
        //mov cs, ax
    }

    psysinfo->cr0 = _cr0;
    psysinfo->cs.raw = _cs;
    psysinfo->ldt.raw = _ldt;
    psysinfo->tr.raw = _tr;
}

SYSINFO sysinfo;

const char *code_or_data_segment[] = {
    "Data   (RO)                       ",
    "Data   (R,               accessed)",
    "Data   (R/W)                      ",
    "Data   (R/W,             accessed)",
    "Data   (RO,  expand-down)         ",
    "Data   (RO,  expand-down,accessed)",
    "Data   (R/W, expand-down)         ",
    "Data   (R/W, expand-down,accessed)",
    "Code   (EO)                       ",
    "Code   (EO,              accessed)",
    "Code   (E/R)                      ",
    "Code   (E/R,             accessed)",
    "Code   (EO,  conforming)          ",
    "Code   (EO,  conforming, accessed)",
    "Code   (E/R, conforming)          ",
    "Code   (E/R, conforming, accessed)"
};

const char *system_segment[] = {
    "System (Reserved                 )",
    "System (16-bit TSS (Available)   )",
    "System (LDT                      )",
    "System (16-bit TSS (Busy)        )",
    "System (16-bit Call Gate         )",
    "System (Task Gate                )",
    "System (16-bit Interrupt Gate    )",
    "System (16-bit Trap Gate         )",
    "System (Reserved                 )",
    "System (32-bit TSS (Available)   )",
    "System (Reserved                 )",
    "System (32-bit TSS (Busy)        )",
    "System (32-bit Call Gate         )",
    "System (Reserved                 )",
    "System (32-bit Interrupt Gate    )",
    "System (32-bit Trap Gate         )"
};

void dump_idt(PSYSINFO sysinfo)
{
    FILE *file = fopen("idt.txt", "w");
    PGATE cur_gate;
    PGATE head = (PGATE)(char *)sysinfo->idt.base;
    PGATE tail = (PGATE)(char *)(sysinfo->idt.base + sysinfo->idt.limit);
    
    if (!file) {
        perror(NULL);
        return;
    }
    
    printf("IDT: base=0x%08X limit=0x%04X\n", sysinfo->idt.base, sysinfo->idt.limit);

    for (cur_gate = head; cur_gate < tail; cur_gate++) {
        if (cur_gate->task.magic == 0x5) {
            fprintf(file, "0x%p: %08X %08X (task) p=%01X dpl=%01X tss=%04X\n", 
                    cur_gate, cur_gate->raw.high, cur_gate->raw.low, 
                    cur_gate->task.p, cur_gate->task.dpl, cur_gate->task.tss);
        } else if ((cur_gate->int_or_trap.magic1 == 0x0) && 
                (cur_gate->int_or_trap.magic2 == 0x6) && 
                (cur_gate->int_or_trap.magic3 == 0x0)) {
            fprintf(file, "0x%p: %08X %08X (intr) p=%01X dpl=%01X sel=%04X d=%01X offset=%08X\n", 
                    cur_gate, cur_gate->raw.high, cur_gate->raw.low, 
                    cur_gate->int_or_trap.p, cur_gate->int_or_trap.dpl, 
                    cur_gate->int_or_trap.segm_sel, cur_gate->int_or_trap.d, 
                    ((uint32)cur_gate->int_or_trap.offset_high << 16) + cur_gate->int_or_trap.offset_low);
        } else if ((cur_gate->int_or_trap.magic1 == 0x0) && 
                (cur_gate->int_or_trap.magic2 == 0x7) && 
                (cur_gate->int_or_trap.magic3 == 0x0)) {
            fprintf(file, "0x%p: %08X %08X (trap) p=%01X dpl=%01X sel=%04X d=%01X offset=%08X\n", 
                    cur_gate, cur_gate->raw.high, cur_gate->raw.low, 
                    cur_gate->int_or_trap.p, cur_gate->int_or_trap.dpl, 
                    cur_gate->int_or_trap.segm_sel, cur_gate->int_or_trap.d, 
                    ((uint32)cur_gate->int_or_trap.offset_high << 16) + cur_gate->int_or_trap.offset_low);
        } else 
            fprintf(file, "0x%p: %08X %08X\n", cur_gate, cur_gate->raw.high, cur_gate->raw.low);
    }

    fclose(file);
}

void dump_ldt(PSYSINFO sysinfo)
{
    FILE *file = fopen("ldt.txt", "w");
    PDESC pdesc = (PDESC)(char *)sysinfo->gdt.base + sysinfo->ldt.index;
    PDESC head = (PDESC)(char *)(((uint32)pdesc->desc.base_low) | 
                    ((uint32)pdesc->desc.base_mid << 16) | 
                    ((uint32)pdesc->desc.base_high << 24));
    uint32 ldt_limit = ((uint32)pdesc->desc.limit_low) | 
                     ((uint32)pdesc->desc.limit_high << 16);
    PDESC cur_desc;
    PDESC tail = head + ldt_limit / sizeof(DESC) * (1 << (pdesc->desc.g ? 12 : 0)) + 1;
    
    if (!file) {
        perror(NULL);
        return;
    }
    
    printf("LDT: selector=0x%04X base=%p limit=0x%08X (Bytes)\n", sysinfo->ldt.raw, head, ldt_limit);

    for (cur_desc = head; cur_desc < tail; cur_desc++) {
        uint32 base = ((uint32)cur_desc->desc.base_low) | 
                        ((uint32)cur_desc->desc.base_mid << 16) | 
                        ((uint32)cur_desc->desc.base_high << 24);
        uint32 limit = ((uint32)cur_desc->desc.limit_low) | 
                        ((uint32)cur_desc->desc.limit_high << 16);
        fprintf(file, "0x%p: %08X %08X - base=%08X limit=%05X (%s) dpl=%01X p=%01X avl=%01X l=%01X db=%01X ", 
                cur_desc, cur_desc->raw.high, cur_desc->raw.low, base, limit, 
				(cur_desc->desc.g ? "Pages" : "Bytes"), cur_desc->desc.dpl, 
                cur_desc->desc.p, cur_desc->desc.avl, cur_desc->desc.l, 
                cur_desc->desc.db);
		if (cur_desc->desc.s)
			fprintf(file, "%*s\n", sizeof(code_or_data_segment[cur_desc->desc.type]),
					code_or_data_segment[cur_desc->desc.type]);
		else
			fprintf(file, "%*s\n", sizeof(system_segment[cur_desc->desc.type]),
					system_segment[cur_desc->desc.type]);				
    }
    
    fclose(file);
}

void dump_gdt(PSYSINFO sysinfo)
{
    FILE *file = fopen("gdt.txt", "w");
    PDESC cur_desc;
    PDESC head = (PDESC)(char *)sysinfo->gdt.base;
    PDESC tail = (PDESC)(char *)(sysinfo->gdt.base + sysinfo->gdt.limit);
    
    if (!file) {
        perror(NULL);
        return;
    }
    
    printf("GDT: base=%p limit=0x%04X\n", head, sysinfo->gdt.limit);

    for (cur_desc = head; cur_desc < tail; cur_desc++) {
        uint32 base = ((uint32)cur_desc->desc.base_low) | 
                        ((uint32)cur_desc->desc.base_mid << 16) | 
                        ((uint32)cur_desc->desc.base_high << 24);
        uint32 limit = ((uint32)cur_desc->desc.limit_low) | 
                        ((uint32)cur_desc->desc.limit_high << 16);
        fprintf(file, "0x%p: %08X %08X - base=%08X limit=%05X (%s) dpl=%01X p=%01X avl=%01X l=%01X db=%01X ", 
                cur_desc, cur_desc->raw.high, cur_desc->raw.low, base, limit, 
				(cur_desc->desc.g ? "Pages" : "Bytes"), cur_desc->desc.dpl, 
                cur_desc->desc.p, cur_desc->desc.avl, cur_desc->desc.l, 
                cur_desc->desc.db);
		if (cur_desc->desc.s)
			fprintf(file, "%*s\n", sizeof(code_or_data_segment[cur_desc->desc.type]),
					code_or_data_segment[cur_desc->desc.type]);
		else
			fprintf(file, "%*s\n", sizeof(system_segment[cur_desc->desc.type]),
					system_segment[cur_desc->desc.type]);				
    }

    fclose(file);
}

#define TSS_IDX 18
#define TSS_LIMIT 0x67
#define TSS_TEST_CR3 0x1337

PTSS create_and_init_tss(DTR* gdt, uint32 offset)
{
	void *addr = (void *)(gdt->base + 8 * offset);
	PDESC pdesc = (PDESC)addr;
	uint16 _sel = offset << 3;
	uint16 _cs, _es, _ss, _ds;
	uint32 _esp;

	PTSS p_tss = calloc(1, sizeof(TSS));
	uint32 ptss = (uint32) p_tss;

	__asm
	{
		mov _cs, cs
		mov _ss, ss
		mov _es, es
		mov _ds, ds
		mov _esp, esp
	}

	p_tss->tssCR3 = TSS_TEST_CR3;
	p_tss->tssCS = _cs;
	p_tss->tssSS = _ss;
	p_tss->tssDS = _ds;
	p_tss->tssES = _es;
	p_tss->tssESP = _esp;
	p_tss->tssEAX = 0xDEADBEEF;

	pdesc->desc.limit_low = (TSS_LIMIT & 0xFFFF);
	pdesc->desc.base_low = (ptss & 0xFFFF);
	pdesc->desc.base_mid = (ptss >> 16) & 0xFF;
	pdesc->desc.type = 0x9;
	pdesc->desc.s = 0;
	pdesc->desc.dpl = 0;
	pdesc->desc.p = 1;
	pdesc->desc.limit_high = (TSS_LIMIT >> 16) & 0xFF;
	pdesc->desc.avl = 0;
	pdesc->desc.l = 0;
	pdesc->desc.db = 0;
	pdesc->desc.g = 0;
	pdesc->desc.base_high = (ptss >> 24) & 0xFF;

	__asm
	{
		push ax
		mov ax, _sel
		ltr ax
		pop ax
	}

	return p_tss;
}

void dump_tss(PSYSINFO psysinfo)
{
	FILE *file = fopen("tss.txt", "w");
	void *addr = (void *)(psysinfo->gdt.base + psysinfo->tr.index << 3);
	PDESC pdesc = (PDESC)addr;
	uint32 base = BASE_FROM_DESCRIPTOR(pdesc);
	uint32 limit = LIMIT_FROM_DESCRIPTOR(pdesc);
	PTSS ptss = (PTSS)base;

	fprintf(file, "TR = 0x%04X, index = %u, TSS (base = 0x%p, limit = 0x%08X):\n", 
			psysinfo->tr, psysinfo->tr.index, base, limit);
	fprintf(file, "s=%01X dpl=%01X p=%01X avl=%01X l=%01X db=%01X g=%01X\n", 
			pdesc->desc.s, pdesc->desc.dpl, pdesc->desc.p, pdesc->desc.avl, 
			pdesc->desc.l, pdesc->desc.db, pdesc->desc.g);
	fprintf(file, "TSS: CR3  = 0x%08X\n", ptss->tssCR3);
    fprintf(file, "TSS: ptl  = 0x%08X    eflags = 0x%08X\n", ptss->ptl, ptss->tssEFLAGS);
    fprintf(file, "TSS: esp0 = 0x%08X    ss0    = 0x%08X\n", ptss->esp0, ptss->ss0);
    fprintf(file, "TSS: esp1 = 0x%08X    ss1    = 0x%08X\n", ptss->esp1, ptss->ss1);
    fprintf(file, "TSS: esp2 = 0x%08X    ss2    = 0x%08X\n", ptss->esp2, ptss->ss2);
    fprintf(file, "TSS: eip  = 0x%08X    ltd_ss = 0x%08X\n", ptss->tssEIP, ptss->ldtss);
    fprintf(file, "TSS: eax  = 0x%08X    ecx    = 0x%08X\n", ptss->tssEAX, ptss->tssECX);
    fprintf(file, "TSS: edx  = 0x%08X    ebx    = 0x%08X\n", ptss->tssEDX, ptss->tssEBX);
    fprintf(file, "TSS: esp  = 0x%08X    ebp    = 0x%08X\n", ptss->tssESP, ptss->tssEBP);
    fprintf(file, "TSS: esi  = 0x%08X    edi    = 0x%08X\n", ptss->tssESI, ptss->tssEDI);
    fprintf(file, "TSS: es   = 0x%08X     cs    = 0x%08X\n", ptss->tssES,  ptss->tssCS);
    fprintf(file, "TSS: ss   = 0x%08X     ds    = 0x%08X\n", ptss->tssSS,  ptss->tssDS);
    fprintf(file, "TSS: fs   = 0x%08X     gs    = 0x%08X\n", ptss->tssFS,  ptss->tssGS);

	fclose(file);
}

void delete_tss(PTSS p_tss)
{
	free(p_tss);
}

void main()
{
	PTSS ptss;
    
	get_sysinfo(&sysinfo);

    printf("0x%08X - %s, %s\n", sysinfo.cr0, 
            sysinfo.cr0 & CR0_PE ? "Protected mode" : "Real mode",
            sysinfo.cr0 & CR0_PG ? "Paging on" : "Paging off");
    printf("0x%08X - %s\n", (int)sysinfo.cs.raw, 
            (sysinfo.cs.pl == 0) ? "Ring 0" : "Ring ?");

    printf("TR = 0x%04X\n", sysinfo.tr.raw);

	ptss = create_and_init_tss(&(sysinfo.gdt), TSS_IDX);
	get_sysinfo(&sysinfo);
    dump_tss(&sysinfo);
    delete_tss(ptss);

    dump_gdt(&sysinfo);
    dump_ldt(&sysinfo);
    dump_idt(&sysinfo);
}
