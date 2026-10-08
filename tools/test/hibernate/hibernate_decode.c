/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Lewis Lakerink
 *
 * Offline ABI 1 hibernate-image prefix decoder.
 *
 * This file is a THIN FRONTEND over the shared codec in
 * sys/kern/kern_hibernate.c.  It contains no independent ELF, CB, or
 * PCB parsing; all structural validation is delegated to
 * hibernate_image_decode() and hibernate_image_interval_next() from the
 * kernel source.
 *
 * Input: the image-relative metadata prefix [0, payload_start).
 * The prefix is the bytes from the start of the hibernate image
 * (hm_image_offset = provider_media_offset + 65536) up to but not
 * including payload_start.  Its length is exactly the value stored in
 * hc_payload_start / hc_metadata_length in the CB, which is at most
 * 65536 bytes (HIBERNATE_META_BUF_MAX).
 *
 * Usage:
 *   hibernate_decode <prefix-file>
 *
 * On a valid golden prefix the tool prints decoded CB/PCB/layout facts
 * and interval coverage to stdout and exits 0.
 *
 * On malformed input it prints a deterministic message to stderr and
 * exits 1.
 *
 * Example — golden success:
 *   $ hibernate_decode good.prefix
 *   hibernate_decode: prefix 4096 bytes
 *   CB  version=1 encoded_size=256
 *   CB  image_length=0x100000000 payload_start=0x1000
 *   CB  physmem_bytes=0x200000000 page_size=4096
 *   CB  destination_pages=131072 destination_bytes=0x200000000
 *   CB  source_vector_bytes=16384
 *   CB  arena_start=0x... arena_size=0x...
 *   CB  facs_hardware_signature=0x...
 *   CB  elf_phnum=3 metadata_length=4096
 *   CB  crc32c=0x...
 *   PCB version=1 encoded_size=1024
 *   PCB cr0=0x... cr3=0x... cr4=0x...
 *   PCB rip=0x... rsp=0x...
 *   PCB xcr0=0x3 xsave_length=576 xsave_format=1
 *   layout: phnum=3 load_segments=1 cb_offset=0x1000 pcb_offset=0x2000
 *   layout: payload_start=0x3000 image_length=0x100000000
 *   intervals:
 *     [0x0000000000000000, 0x0000000000000080) STORED   (ELF header+phdrs)
 *     [0x0000000000000080, 0x0000000000001000) ZERO_GAP
 *     [0x0000000000001000, 0x0000000000001100) STORED   (CB)
 *     [0x0000000000001100, 0x0000000000002000) ZERO_GAP
 *     [0x0000000000002000, 0x0000000000002400) STORED   (PCB)
 *     [0x0000000000002400, 0x0000000000003000) ZERO_GAP
 *     [0x0000000000003000, 0x0000000000100000) ZERO_GAP (payload gap)
 *     [0x0000000000100000, 0x0000000100000000) STORED   (PT_LOAD #0)
 *   done: 2 stored intervals, 5 zero-gap intervals
 *   hibernate_decode: OK
 *
 * Example — malformed refusal:
 *   $ hibernate_decode bad.prefix
 *   hibernate_decode: hibernate_image_decode: EINVAL
 *   $ echo $?
 *   1
 */

#include <sys/mman.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Pull in the shared codec types and prototypes. */
#include <sys/hibernate.h>

static const char *
interval_class_name(enum hibernate_image_interval_class c)
{
	switch (c) {
	case HIIC_STORED:
		return ("STORED");
	case HIIC_ZERO_GAP:
		return ("ZERO_GAP");
	default:
		return ("UNKNOWN");
	}
}

/*
 * errno_name: return a short string for the errnos the codec emits.
 * Not exhaustive; unknown codes fall back to strerror(3).
 */
static const char *
errno_name(int e)
{
	switch (e) {
	case EINVAL:
		return ("EINVAL");
	case EOVERFLOW:
		return ("EOVERFLOW");
	case E2BIG:
		return ("E2BIG");
	case ENOENT:
		return ("ENOENT");
	case ENOTSUP:
		return ("ENOTSUP");
	default:
		return (strerror(e));
	}
}

int
main(int argc, char *argv[])
{
	const char *path;
	int fd, error;
	struct stat st;
	void *buf;
	size_t len;
	struct hibernate_image img;
	struct hibernate_image_iterator it;
	struct hibernate_image_interval iv;
	uint64_t stored_count, gap_count;

	if (argc != 2) {
		fprintf(stderr, "usage: hibernate_decode <prefix-file>\n");
		return (1);
	}
	path = argv[1];

	fd = open(path, O_RDONLY);
	if (fd == -1)
		err(1, "open: %s", path);

	if (fstat(fd, &st) == -1)
		err(1, "fstat: %s", path);

	len = (size_t)st.st_size;
	if (len == 0) {
		fprintf(stderr, "hibernate_decode: %s: empty file\n", path);
		close(fd);
		return (1);
	}
	if (len > HIBERNATE_META_BUF_MAX) {
		fprintf(stderr,
		    "hibernate_decode: %s: file too large (%zu > %u)\n", path,
		    len, HIBERNATE_META_BUF_MAX);
		close(fd);
		return (1);
	}

	buf = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
	if (buf == MAP_FAILED)
		err(1, "mmap: %s", path);
	close(fd);

	printf("hibernate_decode: prefix %zu bytes\n", len);

	error = hibernate_image_decode(buf, len, &img);
	if (error != 0) {
		fprintf(stderr,
		    "hibernate_decode: hibernate_image_decode: %s\n",
		    errno_name(error));
		munmap(buf, len);
		return (1);
	}

	/* Print CB facts. */
	printf("CB  version=%u encoded_size=%u\n", img.hi_cb.hc_version,
	    img.hi_cb.hc_encoded_size);
	printf("CB  image_length=0x%016" PRIx64 " payload_start=0x%016" PRIx64
	       "\n",
	    img.hi_cb.hc_image_length, img.hi_cb.hc_payload_start);
	printf("CB  physmem_bytes=0x%016" PRIx64 " page_size=%" PRIu64 "\n",
	    img.hi_cb.hc_physmem_bytes, img.hi_cb.hc_page_size);
	printf("CB  destination_pages=%" PRIu64
	       " destination_bytes=0x%016" PRIx64 "\n",
	    img.hi_cb.hc_destination_pages, img.hi_cb.hc_destination_bytes);
	printf("CB  source_vector_bytes=%" PRIu64 "\n",
	    img.hi_cb.hc_source_vector_bytes);
	printf("CB  arena_start=0x%016" PRIx64 " arena_size=0x%016" PRIx64 "\n",
	    img.hi_cb.hc_arena_start, img.hi_cb.hc_arena_size);
	printf("CB  facs_hardware_signature=0x%016" PRIx64 "\n",
	    img.hi_cb.hc_facs_hardware_signature);
	printf("CB  elf_phnum=%" PRIu64 " metadata_length=%" PRIu64 "\n",
	    img.hi_cb.hc_elf_phnum, img.hi_cb.hc_metadata_length);
	printf("CB  crc32c=0x%08" PRIx32 "\n", img.hi_cb.hc_crc32c);
	printf("CB  restore_footprint_pages=%" PRIu64 "\n",
	    img.hi_cb.hc_restore_footprint_pages);
	printf("CB  machine_flags=0x%016" PRIx64 " copy_list_bound=%" PRIu64
	       "\n",
	    img.hi_cb.hc_machine_flags, img.hi_cb.hc_copy_list_bound);

	/* Print PCB facts. */
	printf("PCB version=%u encoded_size=%u\n", img.hi_pcb.hp_version,
	    img.hi_pcb.hp_encoded_size);
	printf("PCB cr0=0x%016" PRIx64 " cr3=0x%016" PRIx64 " cr4=0x%016" PRIx64
	       "\n",
	    img.hi_pcb.hp_cr0, img.hi_pcb.hp_cr3, img.hi_pcb.hp_cr4);
	printf("PCB efer=0x%016" PRIx64 " pat=0x%016" PRIx64 "\n",
	    img.hi_pcb.hp_efer, img.hi_pcb.hp_pat);
	printf("PCB rip=0x%016" PRIx64 " rsp=0x%016" PRIx64 "\n",
	    img.hi_pcb.hp_rip, img.hi_pcb.hp_rsp);
	printf("PCB rflags=0x%016" PRIx64 " r12_pcb_pa=0x%016" PRIx64 "\n",
	    img.hi_pcb.hp_rflags, img.hi_pcb.hp_r12_pcb_pa);
	printf("PCB xcr0=0x%016" PRIx64 " xsave_length=%u xsave_format=%u\n",
	    img.hi_pcb.hp_xcr0, img.hi_pcb.hp_xsave_length,
	    img.hi_pcb.hp_xsave_format);
	printf("PCB gdtr_base=0x%016" PRIx64 " gdtr_limit=%u\n",
	    img.hi_pcb.hp_gdtr_base, img.hi_pcb.hp_gdtr_limit);
	printf("PCB idtr_base=0x%016" PRIx64 " idtr_limit=%u\n",
	    img.hi_pcb.hp_idtr_base, img.hi_pcb.hp_idtr_limit);

	/* Print layout facts derived from the decoded image. */
	printf("layout: phnum=%u load_segments=%u cb_offset=0x%016" PRIx64
	       " pcb_offset=0x%016" PRIx64 "\n",
	    img.hi_phnum, img.hi_load_count, img.hi_cb_offset,
	    img.hi_pcb_offset);
	printf("layout: payload_start=0x%016" PRIx64
	       " image_length=0x%016" PRIx64 "\n",
	    img.hi_payload_start, img.hi_image_length);
	printf("layout: crc_zero_offset=0x%016" PRIx64
	       " crc_zero_length=%" PRIu64 "\n",
	    img.hi_crc_zero_offset, img.hi_crc_zero_length);

	/* Walk the interval iterator and print coverage. */
	printf("intervals:\n");
	it.hii_image = &img;
	it.hii_next_index = 0;
	it.hii_cursor = 0;
	it.hii_phase = HIIP_METADATA;
	it.hii_error = 0;

	stored_count = 0;
	gap_count = 0;

	for (;;) {
		error = hibernate_image_interval_next(&it, &iv);
		if (error == ENOENT)
			break;
		if (error != 0) {
			fprintf(stderr,
			    "hibernate_decode: "
			    "hibernate_image_interval_next: %s\n",
			    errno_name(error));
			munmap(buf, len);
			return (1);
		}
		printf("  [0x%016" PRIx64 ", 0x%016" PRIx64 ") %s\n",
		    iv.hii_offset, iv.hii_offset + iv.hii_length,
		    interval_class_name(iv.hii_class));
		if (iv.hii_class == HIIC_STORED)
			stored_count++;
		else
			gap_count++;
	}

	printf("done: %" PRIu64 " stored intervals, %" PRIu64
	       " zero-gap intervals\n",
	    stored_count, gap_count);
	printf("hibernate_decode: OK\n");

	munmap(buf, len);
	return (0);
}
