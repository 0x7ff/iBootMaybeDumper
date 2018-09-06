#include <fcntl.h>
#include <inttypes.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define MIB (1024u * 1024u)
#define ROUND_SZ (512u * MIB)
#define ROUND_MEMSIZE(a) (((a) + (ROUND_SZ - 1)) & ~(ROUND_SZ - 1))
#define SEG_TEXT_VMADDR_9 (0xffffff8004004000ull)
#define SEG_TEXT_VMADDR_10 (0xfffffff007004000ull)
#define IBOOT_START_DUMP_INSN_CNT (16)
#define CHUNK_SZ (0x1000)
#define KADDR_FMT "0x%016" PRIx64
#define RD(a) extract32(a, 0, 5)
#define RN(a) extract32(a, 5, 5)
#define IS_LDR_X(a) (((a) & 0xff000000u) == 0x58000000u)
#define LDR_X_IMM(a) (sextract64(a, 5, 19) << 2u)
#define IS_ADRP(a) (((a) & 0x9f000000u) == 0x90000000u)
#define ADRP_IMM(a) (((sextract64(a, 5, 19) << 2u) | extract32(a, 29, 2)) << 12u)
#define ADRP_ADDR(a) ((a) & ~0xfffull)
#define IS_ADD_X(a) (((a) & 0xffc00000u) == 0x91000000u)
#define ADD_X_IMM(a) extract32(a, 10, 12)

typedef uint64_t kaddr_t;

typedef struct {
	uint16_t Revision;
	uint16_t Version;
	uint32_t padding;
	kaddr_t virtBase;
	kaddr_t physBase;
	kaddr_t memSize;
} boot_args_t;

extern kern_return_t mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

static task_t tfp0 = MACH_PORT_NULL;

static inline uint32_t
extract32(uint32_t value, unsigned start, unsigned length) {
	return (value >> start) & (~0u >> (32u - length));
}

static inline uint64_t
sextract64(uint64_t value, unsigned start, unsigned length) {
	return (uint64_t)((int64_t)(value << (64u - length - start)) >> (64u - length));
}

static bool
is_inited_tfp0(void) {
	mach_port_t host;
	
	if(task_for_pid(mach_task_self_, 0, &tfp0)) {
		host = mach_host_self();
		host_get_special_port(host, HOST_LOCAL_NODE, 4, &tfp0);
		mach_port_deallocate(mach_task_self_, host);
	}
	return MACH_PORT_VALID(tfp0);
}

static kern_return_t
read_kbytes(mach_vm_address_t addr, void *out, mach_vm_size_t out_sz) {
	mach_vm_size_t n, last, sz = 0;
	
	if(out_sz <= CHUNK_SZ) {
		return mach_vm_read_overwrite(tfp0, addr, out_sz, (mach_vm_address_t)out, &sz);
	}
	
	for(n = 0; n < out_sz; n += CHUNK_SZ) {
		if(mach_vm_read_overwrite(tfp0, addr + n, CHUNK_SZ, (mach_vm_address_t)out, &sz)) {
			return KERN_FAILURE;
		}
	}
	
	if((last = out_sz - n) && mach_vm_read_overwrite(tfp0, addr + n, last, (mach_vm_address_t)out, &sz)) {
		return KERN_FAILURE;
	}
	
	return KERN_SUCCESS;
}

static kaddr_t
find_entry(kaddr_t kernel_base) {
	const arm_unified_thread_state_t *state;
	const struct thread_command *tc;
	struct mach_header_64 mh64;
	kaddr_t pc = 0;
	uint32_t i;
	void *ptr;
	
	if(!read_kbytes(kernel_base, &mh64, sizeof(mh64)) &&
	   (ptr = malloc(mh64.sizeofcmds)))
	{
		if(!read_kbytes(kernel_base + sizeof(mh64), ptr, mh64.sizeofcmds)) {
			tc = (const struct thread_command *)ptr;
			for(i = 0; i < mh64.ncmds; ++i) {
				if(tc->cmd == LC_UNIXTHREAD) {
					state = (const arm_unified_thread_state_t *)((uintptr_t)tc + sizeof(*tc));
					if(state->ash.count == ARM_THREAD_STATE64_COUNT &&
					   state->ash.flavor == ARM_THREAD_STATE64)
					{
						pc = state->ts_64.__pc;
						break;
					}
				}
				tc = (const struct thread_command *)((uintptr_t)tc + tc->cmdsize);
			}
		}
		free(ptr);
	}
	return pc;
}

static kaddr_t
find_const_boot_args(kaddr_t entry) {
	kaddr_t rvbar = entry & ~0xfffull, rvbar_sz = entry & 0xfffu, imm = 0, i;
	uint32_t *insn;
	
	if((insn = malloc(rvbar_sz))) {
		if(!read_kbytes(rvbar, insn, rvbar_sz)) {
			for(i = 0; i < rvbar_sz / (2 * sizeof(*insn)); ++i) {
				if(IS_ADRP(insn[i]) &&
				   RD(insn[i]) == 20 &&
				   IS_ADD_X(insn[i + 1]) &&
				   RD(insn[i + 1]) == 20 &&
				   RN(insn[i + 1]) == 20)
				{
					imm = ADRP_ADDR(entry + (i * sizeof(*insn))) + ADRP_IMM(insn[i]) + ADD_X_IMM(insn[i + 1]);
					break;
				}
			}
		}
		free(insn);
	}
	return imm;
}

static void
dump_iboot(kaddr_t gVirtBase, kaddr_t gPhysBase, kaddr_t gPhysSize, kaddr_t iboot_load_addr, const char *filename) {
	uint32_t insn[IBOOT_START_DUMP_INSN_CNT];
	kaddr_t iboot_sz, iboot_end;
	void *iboot;
	size_t i;
	int fd;
	
	if((fd = open(filename, O_TRUNC | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) != -1) {
		if(!read_kbytes(iboot_load_addr - gPhysBase + gVirtBase, insn, sizeof(insn))) {
			for(i = 0; i < IBOOT_START_DUMP_INSN_CNT; ++i) {
				if(IS_LDR_X(insn[i]) &&
				   RD(insn[i]) == 2 &&
				   (iboot_end = LDR_X_IMM(insn[i])) > iboot_load_addr)
				{
					iboot_sz = iboot_end - iboot_load_addr;
					printf("iboot_sz: " KADDR_FMT "\n", iboot_sz);
					if((iboot_end - gPhysBase) < gPhysSize &&
					   (iboot = malloc(iboot_sz)))
					{
						if(!read_kbytes(iboot_load_addr - gPhysBase + gVirtBase, iboot, iboot_sz) && write(fd, iboot, iboot_sz) != -1)
						{
							printf("Dumped iBoot to file %s\n", filename);
							i = IBOOT_START_DUMP_INSN_CNT;
						}
						free(iboot);
					}
				}
			}
		}
		close(fd);
	}
}

int
main(int argc, char **argv) {
	kaddr_t entry, slide, kernel_base, const_boot_args, iboot_load_addr;
	boot_args_t boot_args;
	
	if(argc != 3) {
		printf("Usage: %s kernel_base iBoot_out\n", argv[0]);
	} else if(sscanf(argv[1], KADDR_FMT, &kernel_base) == 1) {
		if(is_inited_tfp0()) {
			printf("kernel_base: " KADDR_FMT "\n", kernel_base);
			if((entry = find_entry(kernel_base))) {
				printf("entry: " KADDR_FMT "\n", entry);
				slide = (kernel_base > SEG_TEXT_VMADDR_10) ? (kernel_base - SEG_TEXT_VMADDR_10) : (kernel_base - SEG_TEXT_VMADDR_9);
				if((const_boot_args = find_const_boot_args(entry + slide))) {
					printf("const_boot_args: " KADDR_FMT "\n", const_boot_args);
					if(!read_kbytes(const_boot_args, &boot_args, sizeof(boot_args))) {
						printf("gVirtBase: " KADDR_FMT "\n", boot_args.virtBase);
						printf("gPhysBase: " KADDR_FMT "\n", boot_args.physBase);
						printf("gPhysSize: " KADDR_FMT "\n", boot_args.memSize);
						iboot_load_addr = 0x800000000ull + ROUND_MEMSIZE(boot_args.memSize) - (256u * MIB);
						printf("iboot_load_addr: " KADDR_FMT "\n", iboot_load_addr);
						dump_iboot(boot_args.virtBase, boot_args.physBase, boot_args.memSize, iboot_load_addr, argv[2]);
					}
				}
			}
			mach_port_deallocate(mach_task_self_, tfp0);
		}
	}
}
