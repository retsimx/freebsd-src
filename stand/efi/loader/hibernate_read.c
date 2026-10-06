/*-
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by Konstantin Belousov <kib@FreeBSD.org>, and
 * Olivier Certner <olce@FreeBSD.org> at Kumacom SARL, under sponsorship from
 * the FreeBSD Foundation.
 */

#include <sys/cdefs.h>
#include <sys/param.h>

#if defined(__amd64__)

#define __ELF_WORD_SIZE 64
#include <sys/elf_common.h>
#include <machine/elf.h>
#include <machine/hibernate.h>
#include <string.h>
#include <stand.h>

#include <efi.h>
#include <efilib.h>

#include "loader_efi.h"

#define HIBERNATE_IMAGE_OFFSET	65536ULL	/* 64 KiB = LBA 128 at 512b */
#define HIBERNATE_HDR_BUF_SIZE	(512 * 1024)	/* 512 KiB */

static void
hibernate_refuse(const char *reason)
{
	static char report[512];
	size_t used;

	if (reason == NULL)
		reason = "unspecified refusal";
	used = (size_t)snprintf(report, sizeof(report),
	    "Hibernate refusal: %s\n", reason);
	if (used >= sizeof(report))
		report[sizeof(report) - 1] = '\0';
	printf("%s", report);
}

static bool
hibernate_resume_enabled(void)
{
	const char *var;

	var = getenv("hibernate_resume");
	if (var == NULL)
		return (false);
	if (strcmp(var, "YES") == 0 || strcmp(var, "\"YES\"") == 0 ||
	    strcasecmp(var, "yes") == 0 || strcasecmp(var, "\"yes\"") == 0 ||
	    strcmp(var, "1") == 0 || strcmp(var, "\"1\"") == 0)
		return (true);
	return (false);
}

static bool
hibernate_probe_partition(pdinfo_t *part, uint8_t *buf)
{
	EFI_BLOCK_IO *blkio;
	EFI_STATUS status;
	Elf_Ehdr *ehdr;
	Elf_Phdr *ph;
	struct hibernate_cb *cb;
	struct hibernate_pcb *pcb;
	uint64_t blocks_needed, lba, total_mem;
	uint32_t blksz;
	u_int i, load_chunks;

	blkio = part->pd_blkio;
	if (blkio == NULL || blkio->Media == NULL)
		return (false);

	blksz = blkio->Media->BlockSize;
	if (blksz == 0 || (blksz & (blksz - 1)) != 0)
		return (false);

	if (HIBERNATE_IMAGE_OFFSET % blksz != 0)
		return (false);

	lba = HIBERNATE_IMAGE_OFFSET / blksz;
	if (blkio->Media->LastBlock < lba)
		return (false);

	/* Read 1 block to probe for ELF header */
	status = blkio->ReadBlocks(blkio, blkio->Media->MediaId, lba,
	    blksz, buf);
	if (status != EFI_SUCCESS)
		return (false);

	ehdr = (Elf_Ehdr *)buf;
	if (!IS_ELF(*ehdr))
		return (false);
	if (ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr->e_ident[EI_DATA] != ELFDATA2LSB)
		return (false);
	if (ehdr->e_ident[EI_VERSION] != EV_CURRENT)
		return (false);
	if (ehdr->e_version != 0 && ehdr->e_version != EV_CURRENT)
		return (false);
	if (ehdr->e_type != ET_FREEBSD_HIBERNATE_IMAGE)
		return (false);
	if (ehdr->e_machine != EM_X86_64)
		return (false);
	if (ehdr->e_phentsize != sizeof(Elf_Phdr))
		return (false);

	/* Candidate image partition found; read complete 512 KiB headers */
	blocks_needed = HIBERNATE_HDR_BUF_SIZE / blksz;
	if (lba + blocks_needed - 1 > blkio->Media->LastBlock) {
		printf("Hibernate: partition %u too small for headers\n",
		    part->pd_unit);
		hibernate_refuse("read failed");
		return (false);
	}

	status = blkio->ReadBlocks(blkio, blkio->Media->MediaId, lba,
	    HIBERNATE_HDR_BUF_SIZE, buf);
	if (status != EFI_SUCCESS) {
		printf("Hibernate: failed to read headers from partition %u (%lu)\n",
		    part->pd_unit, DECODE_ERROR(status));
		hibernate_refuse("read failed");
		return (false);
	}

	ehdr = (Elf_Ehdr *)buf;
	if (ehdr->e_phnum < 2) {
		printf("Hibernate: invalid phnum %u (expected >= 2)\n",
		    (u_int)ehdr->e_phnum);
		hibernate_refuse("bad phdr layout");
		return (false);
	}

	if (ehdr->e_phoff + (uint64_t)ehdr->e_phnum * sizeof(Elf_Phdr) >
	    HIBERNATE_HDR_BUF_SIZE) {
		printf("Hibernate: phdrs exceed buffer size (phoff 0x%jx, phnum %u)\n",
		    (uintmax_t)ehdr->e_phoff, (u_int)ehdr->e_phnum);
		hibernate_refuse("bad phdr layout");
		return (false);
	}

	ph = (Elf_Phdr *)(buf + ehdr->e_phoff);

	/* Validate phdr[0]: PT_FREEBSD_HIBERNATE_CB */
	if (ph[0].p_type != PT_FREEBSD_HIBERNATE_CB) {
		printf("Hibernate: phdr[0] is not PT_FREEBSD_HIBERNATE_CB (type 0x%x)\n",
		    ph[0].p_type);
		hibernate_refuse("bad phdr layout");
		return (false);
	}
	if (ph[0].p_offset + ph[0].p_filesz > HIBERNATE_HDR_BUF_SIZE) {
		printf("Hibernate: CB exceeds buffer size (offset 0x%jx, size 0x%jx)\n",
		    (uintmax_t)ph[0].p_offset, (uintmax_t)ph[0].p_filesz);
		hibernate_refuse("bad phdr layout");
		return (false);
	}
	cb = (struct hibernate_cb *)(buf + ph[0].p_offset);
	if (!hcb_validate(cb, ph[0].p_filesz)) {
		printf("Hibernate: CB validation failed (version %ju, size %ju)\n",
		    (uintmax_t)cb->hc_version, (uintmax_t)ph[0].p_filesz);
		hibernate_refuse("CB validation failed");
		return (false);
	}

	/* Validate phdr[1]: PT_FREEBSD_HIBERNATE_PCB */
	if (ph[1].p_type != PT_FREEBSD_HIBERNATE_PCB) {
		printf("Hibernate: phdr[1] is not PT_FREEBSD_HIBERNATE_PCB (type 0x%x)\n",
		    ph[1].p_type);
		hibernate_refuse("bad phdr layout");
		return (false);
	}
	if (ph[1].p_filesz != sizeof(struct hibernate_pcb) ||
	    ph[1].p_memsz != sizeof(struct hibernate_pcb)) {
		printf("Hibernate: PCB invalid size (filesz %ju, memsz %ju, expected %zu)\n",
		    (uintmax_t)ph[1].p_filesz, (uintmax_t)ph[1].p_memsz,
		    sizeof(struct hibernate_pcb));
		hibernate_refuse("PCB size mismatch");
		return (false);
	}
	if (ph[1].p_offset + ph[1].p_filesz > HIBERNATE_HDR_BUF_SIZE) {
		printf("Hibernate: PCB exceeds buffer size (offset 0x%jx, size 0x%jx)\n",
		    (uintmax_t)ph[1].p_offset, (uintmax_t)ph[1].p_filesz);
		hibernate_refuse("PCB size mismatch");
		return (false);
	}
	pcb = (struct hibernate_pcb *)(buf + ph[1].p_offset);

	/* Validate phdr[2..N+1]: PT_LOAD */
	load_chunks = 0;
	total_mem = 0;
	for (i = 2; i < ehdr->e_phnum; i++) {
		if (ph[i].p_type != PT_LOAD) {
			printf("Hibernate: phdr[%u] is not PT_LOAD (type 0x%x)\n",
			    i, ph[i].p_type);
			hibernate_refuse("bad phdr layout");
			return (false);
		}
		load_chunks++;
		total_mem += ph[i].p_filesz;
	}

	/* Descriptive summary to serial console */
	printf("=== Hibernate Image Probe (Read-Only Bring-Up) ===\n");
	printf("Hibernate: found image on partition %u (LBA %ju, blocksize %u)\n",
	    part->pd_unit, (uintmax_t)lba, blksz);
	printf("Hibernate ELF Header:\n");
	printf("  type: 0x%04x  machine: 0x%04x  phnum: %u  phentsize: %u\n",
	    ehdr->e_type, ehdr->e_machine, (u_int)ehdr->e_phnum,
	    (u_int)ehdr->e_phentsize);
	printf("Hibernate Control Block (CB):\n");
	printf("  version: %ju\n", (uintmax_t)cb->hc_version);
	printf("  hardware_signature: 0x%016jx\n",
	    (uintmax_t)cb->hc_hardware_signature);
	printf("  contig_spare_start: 0x%016jx  contig_spare_size: 0x%jx (%ju KiB)\n",
	    (uintmax_t)cb->hc_contig_spare_start,
	    (uintmax_t)cb->hc_contig_spare_size,
	    (uintmax_t)(cb->hc_contig_spare_size / 1024));
	printf("  spare_pages_nb: %ju (%ju KiB)\n",
	    (uintmax_t)cb->hc_spare_pages_nb,
	    (uintmax_t)(cb->hc_spare_pages_nb * 4));
	printf("Hibernate Process Control Block (PCB):\n");
	printf("  cr0: 0x%016jx  cr3: 0x%016jx  cr4: 0x%016jx\n",
	    (uintmax_t)pcb->cr0, (uintmax_t)pcb->cr3, (uintmax_t)pcb->cr4);
	printf("  rsp: 0x%016jx  rip: 0x%016jx  r12: 0x%016jx\n",
	    (uintmax_t)pcb->rsp, (uintmax_t)pcb->rip, (uintmax_t)pcb->r12);
	printf("Hibernate PT_LOAD Segments: %u chunks, total %ju bytes (%ju MiB)\n",
	    load_chunks, (uintmax_t)total_mem,
	    (uintmax_t)(total_mem / (1024 * 1024)));
	for (i = 2; i < ehdr->e_phnum; i++) {
		printf("  chunk %2u: paddr 0x%016jx size 0x%08jx (%ju KiB) offset 0x%jx\n",
		    i - 2, (uintmax_t)ph[i].p_paddr, (uintmax_t)ph[i].p_filesz,
		    (uintmax_t)(ph[i].p_filesz / 1024),
		    (uintmax_t)ph[i].p_offset);
	}
	printf("=== Validation Successful: Continuing Normal Boot ===\n");
	return (true);
}

void
hibernate_probe(void)
{
	pdinfo_t *dp, *parent, *part;
	EFI_STATUS status;
	uint8_t *buf;
	bool found;

	if (!hibernate_resume_enabled())
		return;

	if (boot_img == NULL || boot_img->DeviceHandle == NULL) {
		printf("Hibernate: boot_img or DeviceHandle is NULL\n");
		hibernate_refuse("allocation failed");
		return;
	}

	dp = efiblk_get_pdinfo_by_handle(boot_img->DeviceHandle);
	if (dp == NULL) {
		printf("Hibernate: cannot find pdinfo for boot device\n");
		hibernate_refuse("allocation failed");
		return;
	}

	parent = (dp->pd_parent != NULL) ? dp->pd_parent : dp;
	buf = NULL;
	status = BS->AllocatePool(EfiBootServicesData, HIBERNATE_HDR_BUF_SIZE,
	    (void **)&buf);
	if (status != EFI_SUCCESS || buf == NULL) {
		printf("Hibernate: failed to allocate %u bytes header buffer (%lu)\n",
		    (u_int)HIBERNATE_HDR_BUF_SIZE, DECODE_ERROR(status));
		hibernate_refuse("allocation failed");
		return;
	}

	found = false;
	STAILQ_FOREACH(part, &parent->pd_part, pd_link) {
		if (hibernate_probe_partition(part, buf)) {
			found = true;
			break;
		}
	}

	if (!found)
		hibernate_refuse("no hibernate image found");

	BS->FreePool(buf);
}

#else /* !defined(__amd64__) */

void
hibernate_probe(void)
{
}

#endif /* defined(__amd64__) */
