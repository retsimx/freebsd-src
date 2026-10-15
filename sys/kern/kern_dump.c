/*-
 * Copyright (c) 2002 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * _HIBERNATE_DUMP_EXTENT_TEST: narrow test-build mode.
 *
 * When this macro is defined, only dumpsys_hibernate_start() and the
 * minimum headers it requires are compiled.  No other kernel symbols,
 * functions, or types are exposed.  The normal kernel build is the full
 * translation unit.
 */
#ifndef _HIBERNATE_DUMP_EXTENT_TEST
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/callout.h>
#include <sys/conf.h>
#include <sys/endian.h>
#include <sys/hibernate.h>
#include <sys/cons.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/kerneldump.h>
#include <sys/malloc.h>
#include <sys/msgbuf.h>
#include <sys/proc.h>
#include <sys/smp.h>
#include <sys/sysctl.h>
#include <sys/watchdog.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_page.h>
#include <vm/vm_pagequeue.h>
#include <vm/vm_phys.h>
#include <vm/vm_dumpset.h>
#include <vm/pmap.h>

#include <machine/_inttypes.h>
#include <machine/dump.h>
#include <machine/elf.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/vmparam.h>
#ifdef OS_HIBERNATE_SUPPORT
#include <machine/hibernate.h>
#endif

CTASSERT(sizeof(struct kerneldumpheader) == 512);

#define	MD_ALIGN(x)		roundup2((x), PAGE_SIZE)
#define	DEV_ALIGN(x, blocksize)	roundup2((x), (blocksize))

/* Handle buffered writes. */
static size_t fragsz;

struct dump_pa dump_map[DUMPSYS_MD_PA_NPAIRS];

bool
has_dumpers(void)
{
	bool res;

	mtx_lock(&dumpconf_list_lk);
	res = TAILQ_EMPTY(&dumper_configs);
	mtx_unlock(&dumpconf_list_lk);
	return (!res);
}

#if !defined(__powerpc__)
void
dumpsys_gen_pa_init(void)
{
	int n, idx;

	bzero(dump_map, sizeof(dump_map));
	for (n = 0; n < nitems(dump_map); n++) {
		idx = n * 2;
		if (dump_avail[idx] == 0 && dump_avail[idx + 1] == 0)
			break;
		dump_map[n].pa_start = dump_avail[idx];
		dump_map[n].pa_size = dump_avail[idx + 1] - dump_avail[idx];
	}
}
#endif

struct dump_pa *
dumpsys_gen_pa_next(struct dump_pa *mdp)
{

	if (mdp == NULL)
		return (&dump_map[0]);

	mdp++;
	if (mdp - dump_map >= nitems(dump_map) ||
	    (mdp->pa_start == 0 && mdp->pa_size == 0))
		mdp = NULL;
	return (mdp);
}

void
dumpsys_gen_wbinv_all(void)
{

}

void
dumpsys_gen_unmap_chunk(vm_paddr_t pa __unused, size_t chunk __unused,
    void *va __unused)
{

}

int
dumpsys_gen_write_aux_headers(struct dumperinfo *di)
{

	return (0);
}

int
dumpsys_buf_seek(struct dumperinfo *di, size_t sz)
{
	static uint8_t buf[DEV_BSIZE];
	size_t nbytes;
	int error;

	bzero(buf, sizeof(buf));

	while (sz > 0) {
		nbytes = MIN(sz, sizeof(buf));

		error = dump_append(di, buf, nbytes);
		if (error)
			return (error);
		sz -= nbytes;
	}

	return (0);
}

int
dumpsys_buf_write(struct dumperinfo *di, const char *ptr, size_t sz)
{
	size_t len;
	int error;

	while (sz) {
		len = di->blocksize - fragsz;
		if (len > sz)
			len = sz;
		memcpy((char *)di->blockbuf + fragsz, ptr, len);
		fragsz += len;
		ptr += len;
		sz -= len;
		if (fragsz == di->blocksize) {
			error = dump_append(di, di->blockbuf, di->blocksize);
			if (error)
				return (error);
			fragsz = 0;
		}
	}
	return (0);
}

int
dumpsys_buf_flush(struct dumperinfo *di)
{
	int error;

	if (fragsz == 0)
		return (0);

	error = dump_append(di, di->blockbuf, di->blocksize);
	fragsz = 0;
	return (error);
}

CTASSERT(PAGE_SHIFT < 20);
#define PG2MB(pgs) ((pgs + (1 << (20 - PAGE_SHIFT)) - 1) >> (20 - PAGE_SHIFT))

int
dumpsys_cb_dumpdata(struct dump_pa *mdp, int seqnr, void *arg)
{
	struct dumperinfo *di = (struct dumperinfo*)arg;
	vm_paddr_t pa;
	void *va;
	uint64_t pgs;
	size_t counter, sz, chunk;
	int c, error;
	u_int maxdumppgs;

	error = 0;	/* catch case in which chunk size is 0 */
	counter = 0;	/* Update twiddle every 16MB */
	va = NULL;
	pgs = mdp->pa_size / PAGE_SIZE;
	pa = mdp->pa_start;
	maxdumppgs = min(di->maxiosize / PAGE_SIZE, MAXDUMPPGS);
	if (maxdumppgs == 0)	/* seatbelt */
		maxdumppgs = 1;

	printf("  chunk %d: %juMB (%ju pages)", seqnr, (uintmax_t)PG2MB(pgs),
	    (uintmax_t)pgs);

	dumpsys_wbinv_all();
	while (pgs) {
		chunk = pgs;
		if (chunk > maxdumppgs)
			chunk = maxdumppgs;
		sz = chunk << PAGE_SHIFT;
		counter += sz;
		if (counter >> 24) {
			printf(" %ju", (uintmax_t)PG2MB(pgs));
			counter &= (1 << 24) - 1;
		}

		dumpsys_map_chunk(pa, chunk, &va);
		wdog_kern_pat(WD_LASTVAL);

		error = dump_append(di, va, sz);
		dumpsys_unmap_chunk(pa, chunk, va);
		if (error)
			break;
		pgs -= chunk;
		pa += sz;

		/* Check for user abort. */
		c = cncheckc();
		if (c == 0x03)
			return (ECANCELED);
		if (c != -1)
			printf(" (CTRL-C to abort) ");
	}
	printf(" ... %s\n", (error) ? "fail" : "ok");
	return (error);
}

int
dumpsys_foreach_chunk(dumpsys_callback_t cb, void *arg)
{
	struct dump_pa *mdp;
	int error, seqnr;

	seqnr = 0;
	mdp = dumpsys_pa_next(NULL);
	while (mdp != NULL) {
		error = (*cb)(mdp, seqnr++, arg);
		if (error)
			return (-error);
		mdp = dumpsys_pa_next(mdp);
	}
	return (seqnr);
}

static uint64_t fileofs;

static int
cb_dumphdr(struct dump_pa *mdp, int seqnr, void *arg)
{
	struct dumperinfo *di = (struct dumperinfo*)arg;
	Elf_Phdr phdr;
	uint64_t size;
	int error;

	size = mdp->pa_size;
	bzero(&phdr, sizeof(phdr));
	phdr.p_type = PT_LOAD;
	phdr.p_flags = PF_R;			/* XXX */
	phdr.p_offset = fileofs;
#ifdef __powerpc__
	phdr.p_vaddr = (do_minidump? mdp->pa_start : ~0L);
	phdr.p_paddr = (do_minidump? ~0L : mdp->pa_start);
#else
	phdr.p_vaddr = mdp->pa_start;
	phdr.p_paddr = mdp->pa_start;
#endif
	phdr.p_filesz = size;
	phdr.p_memsz = size;
	phdr.p_align = PAGE_SIZE;

	error = dumpsys_buf_write(di, (char*)&phdr, sizeof(phdr));
	fileofs += phdr.p_filesz;
	return (error);
}

static int
cb_size(struct dump_pa *mdp, int seqnr, void *arg)
{
	uint64_t *sz;

	sz = (uint64_t *)arg;
	*sz += (uint64_t)mdp->pa_size;
	return (0);
}

#ifdef OS_HIBERNATE_SUPPORT

SYSCTL_DECL(_debug_acpi);

static int hibernate_spare_mb = 512;
SYSCTL_INT(_debug_acpi, OID_AUTO, hibernate_spare_mb, CTLFLAG_RWTUN,
    &hibernate_spare_mb, 0,
    "Hibernate spare staging memory in megabytes (default 512)");

const uint64_t contig_spare_pages_nb = howmany(HIBERNATE_CONTIG_SPARE_SIZE,
    PAGE_SIZE);

int
dumpsys_hibernate_create_hcb(uint64_t hardware_signature,
    struct hibernate_save_cb **hcb_out)
{
	const int max_contig_tries = 2;
	const int max_spare_tries = 2;
	const int spare_pages_reclaim_slop = 3;
	/*
	 * For now, VM_ALLOC_NODUMP doesn't matter as we do only full dumps, so
	 * we need to zero the spare pages since they are going to disk.
	 *
	 * XXX - We probably need a distinct flag anyway, or better exclude
	 * allocated pages for the HCB while dumping through lookups to what we
	 * have allocated.
	 */
	const int vm_req = VM_ALLOC_NOWAIT | VM_ALLOC_ZERO | VM_ALLOC_NODUMP;
	struct hibernate_save_cb *hcb;
	vm_page_t p;
	uint64_t spare_mb, spare_pages_nb;
	int contig_tries = 0;
	int error;

	spare_mb = (hibernate_spare_mb > 0) ? (uint64_t)hibernate_spare_mb : 512;
	if (spare_mb < 128)
		spare_mb = 128;
	if (spare_mb > 512)
		spare_mb = 512;
	if ((spare_mb * 1024 * 1024) > ((uint64_t)physmem * PAGE_SIZE) / 2)
		spare_mb = (((uint64_t)physmem * PAGE_SIZE) / 2) / (1024 * 1024);
	spare_pages_nb = howmany(spare_mb * 1024 * 1024, PAGE_SIZE);

	/* Allocate the control block. */
	hcb = malloc(hcb_size_spec(spare_pages_nb), M_TEMP, M_WAITOK | M_ZERO);

	hcb->hc_version = HCB_VERSION;
	hcb->hc_spare_pages_nb = spare_pages_nb;

	/* Allocate the contiguous chunk first for better chances of success. */
	hcb->hc_contig_spare_size = contig_spare_pages_nb * PAGE_SIZE;
	for (;;) {
		p = vm_page_alloc_noobj_contig(vm_req, contig_spare_pages_nb,
		    HIBERNATE_PADDR_MIN, -1, PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);
		if (p != NULL)
			break;
		if (++contig_tries >= max_contig_tries) {
			error = ENOMEM;
			goto free_hcb;
		}

		/*
		 * We try to reclaim contiguous memory once.  System is
		 * quiescent at this point, and we got rid of caches, so if
		 * allocation does not work after the reclaim, something is
		 * wrong and there's probably no point in retrying.
		 */
		error = vm_page_reclaim_contig(vm_req, contig_spare_pages_nb,
		    HIBERNATE_PADDR_MIN, -1, PAGE_SIZE, 0);
		if (error != 0)
			goto free_hcb;
	}
	hcb->hc_contig_spare_start = VM_PAGE_TO_PHYS(p);

	/* Non-contiguous pages. */
	for (uint64_t i = 0; i < spare_pages_nb; ++i) {
		vm_page_t p;
		int spare_tries = 0;

		for (;;) {
			p = vm_page_alloc_noobj_contig(vm_req |
			    VM_ALLOC_COUNT(min(VM_ALLOC_COUNT_MAX,
			    spare_pages_nb - i)),
			    1, HIBERNATE_PADDR_MIN, -1, PAGE_SIZE, 0,
			    VM_MEMATTR_DEFAULT);
			if (p != NULL)
				break;
			if (++spare_tries >= max_spare_tries) {
				error = ENOMEM;
				goto free_hcb;
			}

			/* Try to reclaim pages in the wanted physical range. */
			error = vm_page_reclaim_contig(vm_req,
			    spare_pages_reclaim_slop, HIBERNATE_PADDR_MIN, -1,
			    PAGE_SIZE, 0);
			if (error != 0)
				goto free_hcb;
		}

		hcb->hc_spare_pages[i] = VM_PAGE_TO_PHYS(p);
	}

	hcb->hc_hardware_signature = hardware_signature;

	*hcb_out = hcb;
	return (0);

free_hcb:
	dumpsys_hibernate_free_hcb(hcb);
	MPASS(error != 0);
	return (error);
}

void
dumpsys_hibernate_free_hcb(struct hibernate_save_cb *hcb)
{
	vm_paddr_t phys;
	vm_page_t p;

	/* Dealloc contiguous pages. */
	phys = hcb->hc_contig_spare_start;
	if (phys != 0) {
		const uint64_t contig_spare_pages_nb =
		    hcb->hc_contig_spare_size / PAGE_SIZE;

		p = PHYS_TO_VM_PAGE(phys);
		for (uint64_t i = 0; i < contig_spare_pages_nb; ++i)
			vm_page_free(p + i);
	}

	for (uint64_t i = 0; i < hcb->hc_spare_pages_nb; ++i) {
		phys = hcb->hc_spare_pages[i];

		if (phys != 0)
			vm_page_free(PHYS_TO_VM_PAGE(phys));
	}

	free(hcb, M_TEMP);
}

#endif /* OS_HIBERNATE_SUPPORT */

#endif /* !_HIBERNATE_DUMP_EXTENT_TEST */

#ifndef _HIBERNATE_DUMP_EXTENT_TEST
static dumper_start_t dumpsys_hibernate_start;
static dumper_hdr_t dumpsys_hibernate_aux_headers;
#endif /* !_HIBERNATE_DUMP_EXTENT_TEST */


int
dumpsys_hibernate_start(struct dumperinfo *di, struct kerneldumpheader *kdh,
    void *key, uint32_t keysize)
{
	uint64_t D, S;
	const uint64_t M = SIZEOF_METADATA;
	const uint64_t P = (uint64_t)di->mediasize;

	D = dtoh64(kdh->dumpextent);

	/*
	 * K-18: guard M + D against unsigned overflow before comparing with P.
	 * A wrapped span would make an impossible request appear to fit.
	 */
	if (__builtin_add_overflow(M, D, &S))
		return (E2BIG);

	/*
	 * From this point on, logic is similar to that of dump_start().
	 * Difference is that we don't output the dump at the end of the
	 * partition, but at start (modulo SIZEOF_METADATA), since we don't
	 * output an additional header at the end which would indicate
	 * immediately where the dump starts.
	 */
	if (P < S) {
		if (di->kdcomp == NULL)
			return (E2BIG);

		/*
		 * K-18: guard P - M against underflow.  Compression reduces
		 * payload size but cannot remove the fixed metadata prefix.
		 */
		if (P < M)
			return (E2BIG);

		/*
		 * Use all space, hoping that compression will allow the dump to
		 * fit.  Commit the reduced extent only after all refusal checks
		 * pass so that the entry value is preserved on any refusal.
		 *
		 * XXX - This seems unnecessary, as 'dumpextent' is used only in
		 * dump_write_headers() if there's no specific hook, and we have
		 * installed one.
		 */
		D = P - M;
		kdh->dumpextent = htod64(D);
	}

	/*
	 * Write the dump towards the start of the partition.
	 * Set dumpoff only after all refusal checks pass.
	 */
	di->dumpoff = di->mediaoffset + SIZEOF_METADATA;
	return (0);
}

#ifndef _HIBERNATE_DUMP_EXTENT_TEST

/*
 * K-6 canonical ABI-1 provider adapter.
 *
 * The portable core owns image geometry, interval coverage, CRC accounting,
 * and transaction ordering.  This file owns only provider I/O and physical
 * source access.  Every provider write is block-aligned and uses the single
 * caller-preallocated staging buffer.
 */
struct hibernate_provider_stream {
	struct hibernate_attempt *hps_attempt;
	struct hibernate_writer_workspace *hps_workspace;
	struct dumperinfo *hps_dumper;
	uint64_t hps_image_offset;
	uint64_t hps_logical_cursor;
	uint64_t hps_block_file_offset;
	size_t hps_block_used;
	size_t hps_block_size;
	uint8_t *hps_crc_block;
	uint64_t hps_crc_block_file_offset;
	struct hibernate_marker *hps_pending;
	bool hps_crc_block_valid;
};

static int
hibernate_provider_write_block(struct hibernate_provider_stream *stream)
{
	struct hibernate_writer_workspace *workspace;
	uint64_t provider_offset;
	int error;

	workspace = stream->hps_workspace;
	if (stream->hps_block_used != stream->hps_block_size)
		return (EINVAL);
	if (__builtin_add_overflow(stream->hps_image_offset,
		stream->hps_block_file_offset, &provider_offset) ||
	    provider_offset > OFF_MAX)
		return (EOVERFLOW);

	error = dump_write(stream->hps_dumper, workspace->hww_io_buffer,
	    (off_t)provider_offset, stream->hps_block_size);
	if (error != 0)
		return (error);

	if (workspace->hww_plan.hwp_image.hi_crc_zero_offset >=
	    stream->hps_block_file_offset &&
	    workspace->hww_plan.hwp_image.hi_crc_zero_offset <
	    stream->hps_block_file_offset + stream->hps_block_size) {
		memcpy(stream->hps_crc_block, workspace->hww_io_buffer,
		    stream->hps_block_size);
		stream->hps_crc_block_file_offset =
		    stream->hps_block_file_offset;
		stream->hps_crc_block_valid = true;
	}

	stream->hps_block_file_offset += stream->hps_block_size;
	stream->hps_block_used = 0;
	bzero(workspace->hww_io_buffer, stream->hps_block_size);
	return (0);
}

static int
hibernate_provider_append(struct hibernate_provider_stream *stream,
    const void *source, uint64_t length, bool zero, uint32_t *crc)
{
	struct hibernate_writer_workspace *workspace;
	const uint8_t *bytes;
	uint32_t next_crc;
	uint64_t remaining;
	size_t amount;
	int error;

	if (stream == NULL || crc == NULL || length == 0)
		return (EINVAL);
	workspace = stream->hps_workspace;
	bytes = source;
	remaining = length;
	next_crc = *crc;

	while (remaining != 0) {
		amount = MIN((uint64_t)(stream->hps_block_size -
		    stream->hps_block_used), remaining);
		if (zero) {
			bzero(workspace->hww_io_buffer + stream->hps_block_used,
			    amount);
		} else {
			if (bytes == NULL)
				return (EINVAL);
			memcpy(workspace->hww_io_buffer + stream->hps_block_used,
			    bytes, amount);
		}
		next_crc = hibernate_crc32c_update(next_crc,
		    workspace->hww_io_buffer + stream->hps_block_used, amount);
		stream->hps_block_used += amount;
		stream->hps_logical_cursor += amount;
		remaining -= amount;
		if (!zero)
			bytes += amount;

		if (stream->hps_block_used == stream->hps_block_size) {
			error = hibernate_provider_write_block(stream);
			if (error != 0)
				return (error);
		}
	}

	*crc = next_crc;
	return (0);
}

static int
hibernate_provider_stored_source(struct hibernate_provider_stream *stream,
    uint64_t file_offset, uint64_t length, uint32_t *crc)
{
	struct hibernate_writer_workspace *workspace;
	const struct hibernate_writer_run *run;
	uint64_t end, object_end, source_offset;
	size_t i;

	workspace = stream->hps_workspace;
	if (file_offset != stream->hps_logical_cursor ||
	    __builtin_add_overflow(file_offset, length, &end))
		return (EINVAL);

	if (file_offset < workspace->hww_plan.hwp_prefix_length) {
		if (end > workspace->hww_plan.hwp_prefix_length)
			return (EINVAL);
		return (hibernate_provider_append(stream,
		    workspace->hww_prefix + file_offset, length, false, crc));
	}

	if (file_offset == workspace->hww_plan.hwp_image.hi_xsave_offset) {
		if (__builtin_add_overflow(file_offset,
			workspace->hww_plan.hwp_image.hi_xsave_length,
			&object_end) ||
		    end != object_end)
			return (EINVAL);
		return (hibernate_provider_append(stream, workspace->hww_xsave,
		    length, false, crc));
	}

	for (i = 0; i < workspace->hww_plan.hwp_run_count; i++) {
		run = &workspace->hww_runs[i];
		if (__builtin_add_overflow(run->hwr_file_offset,
			run->hwr_length, &object_end))
			return (EOVERFLOW);
		if (file_offset < run->hwr_file_offset || end > object_end)
			continue;

		source_offset = run->hwr_source_offset +
		    (file_offset - run->hwr_file_offset);
		if (!PHYS_IN_DMAP(source_offset) ||
		    source_offset > dmaplimit ||
		    length > dmaplimit - source_offset)
			return (EFAULT);
		return (hibernate_provider_append(stream,
		    PHYS_TO_DMAP(source_offset), length, false, crc));
	}

	return (EINVAL);
}

static int
hibernate_provider_write_stored(void *arg, uint64_t file_offset,
    uint64_t length, uint32_t *crc)
{
	return (hibernate_provider_stored_source(arg, file_offset, length, crc));
}

static int
hibernate_provider_write_zero(void *arg, uint64_t file_offset,
    uint64_t length, uint32_t *crc)
{
	struct hibernate_provider_stream *stream;

	stream = arg;
	if (stream == NULL || file_offset != stream->hps_logical_cursor)
		return (EINVAL);
	return (hibernate_provider_append(stream, NULL, length, true, crc));
}

static int
hibernate_provider_rewrite_crc(void *arg, uint64_t crc_offset,
    uint32_t final_crc)
{
	struct hibernate_provider_stream *stream;
	struct hibernate_writer_workspace *workspace;
	uint64_t provider_offset;
	size_t within;

	stream = arg;
	if (stream == NULL || !stream->hps_crc_block_valid ||
	    crc_offset < stream->hps_crc_block_file_offset ||
	    crc_offset + sizeof(final_crc) >
	    stream->hps_crc_block_file_offset + stream->hps_block_size)
		return (EINVAL);

	workspace = stream->hps_workspace;
	within = (size_t)(crc_offset - stream->hps_crc_block_file_offset);
	le32enc(stream->hps_crc_block + within, final_crc);
	workspace->hww_crc32c = final_crc;
	if (stream->hps_pending == NULL)
		return (EINVAL);
	stream->hps_pending->hm_crc32c = final_crc;

	if (__builtin_add_overflow(stream->hps_image_offset,
		stream->hps_crc_block_file_offset, &provider_offset) ||
	    provider_offset > OFF_MAX)
		return (EOVERFLOW);
	return (dump_write(stream->hps_dumper, stream->hps_crc_block,
	    (off_t)provider_offset, stream->hps_block_size));
}

static int
hibernate_provider_stream_image(void *arg)
{
	struct hibernate_provider_stream *stream;
	int error;

	stream = arg;
	error = hibernate_writer_plan_stream(&stream->hps_workspace->hww_plan,
	    hibernate_provider_write_stored, hibernate_provider_write_zero,
	    hibernate_provider_rewrite_crc, stream);
	if (error != 0)
		return (error);
	if (stream->hps_block_used != 0)
		return (EINVAL);
	if (stream->hps_logical_cursor !=
	    stream->hps_workspace->hww_plan.hwp_image.hi_image_length)
		return (EINVAL);
	return (0);
}

static int
hibernate_writer_plan_live(const struct hibernate_save_cb *hcb,
    const struct hibernate_save_pcb *hpcb, struct hibernate_attempt *attempt,
    const struct vm_phys_reservation *reservation,
    struct hibernate_writer_workspace *workspace)
{
	struct hibernate_xsave_terminal terminal;
	struct hibernate_writer_plan *plan;
	uint64_t destination_pages, image_length, payload_start, xsave_end;
	size_t run_count, i;
	int error;

	if (hcb == NULL || hpcb == NULL || attempt == NULL ||
	    reservation == NULL || workspace == NULL ||
	    workspace->hww_prefix == NULL || workspace->hww_xsave == NULL ||
	    workspace->hww_runs == NULL ||
	    workspace->hww_free_scratch == NULL ||
	    workspace->hww_destination_intervals == NULL ||
	    workspace->hww_xsave_terminal == NULL)
		return (EINVAL);

	error = hibernate_amd64_xsave_collect(workspace->hww_xsave,
	    workspace->hww_xsave_capacity, &terminal);
	if (error != 0)
		return (error);
	*workspace->hww_xsave_terminal = terminal;

	error = hibernate_amd64_pcb_populate(hpcb, &terminal,
	    &workspace->hww_pcb);
	if (error != 0)
		return (error);

	error = hibernate_writer_runs_build(attempt, reservation,
	    workspace->hww_free_scratch, workspace->hww_free_scratch_capacity,
	    0, NULL, 0, &run_count);
	if (error != 0)
		return (error);
	if (run_count == 0 || run_count > workspace->hww_runs_capacity ||
	    run_count > workspace->hww_destination_capacity)
		return (E2BIG);

	error = hibernate_writer_payload_start(run_count, &payload_start);
	if (error != 0)
		return (error);
	workspace->hww_pcb.hp_xsave_offset = payload_start;
	if (__builtin_add_overflow(payload_start, terminal.hxt_length,
		&xsave_end))
		return (EOVERFLOW);

	error = hibernate_writer_runs_build(attempt, reservation,
	    workspace->hww_free_scratch, workspace->hww_free_scratch_capacity,
	    xsave_end, workspace->hww_runs, workspace->hww_runs_capacity,
	    &run_count);
	if (error != 0)
		return (error);

	destination_pages = 0;
	for (i = 0; i < run_count; i++) {
		if (__builtin_add_overflow(destination_pages,
			workspace->hww_runs[i].hwr_length / HIB_PAGE_SIZE,
			&destination_pages))
			return (EOVERFLOW);
		workspace->hww_destination_intervals[i * 2] =
		    workspace->hww_runs[i].hwr_destination;
		workspace->hww_destination_intervals[i * 2 + 1] =
		    workspace->hww_runs[i].hwr_destination +
		    workspace->hww_runs[i].hwr_length;
	}

	if (__builtin_add_overflow(workspace->hww_runs[run_count - 1].
		hwr_file_offset, workspace->hww_runs[run_count - 1].hwr_length,
		&image_length))
		return (EOVERFLOW);

	bzero(&workspace->hww_cb, sizeof(workspace->hww_cb));
	workspace->hww_cb.hc_magic = HIBERNATE_MARKER_MAGIC;
	workspace->hww_cb.hc_version = HCB_VERSION;
	workspace->hww_cb.hc_encoded_size = HIBERNATE_CB_ENCODED_SIZE;
	workspace->hww_cb.hc_page_size = HIB_PAGE_SIZE;
	workspace->hww_cb.hc_physmem_bytes = (uint64_t)physmem * PAGE_SIZE;
	workspace->hww_cb.hc_image_length = image_length;
	workspace->hww_cb.hc_source_vector_bytes =
	    destination_pages * sizeof(uint64_t);
	workspace->hww_cb.hc_arena_start = attempt->ha_arena_start;
	workspace->hww_cb.hc_arena_size = attempt->ha_arena_size;
	workspace->hww_cb.hc_facs_hardware_signature =
	    hcb->hc_hardware_signature;
	workspace->hww_cb.hc_restore_footprint_pages =
	    hibernate_footprint_effective();
	workspace->hww_cb.hc_copy_list_bound = destination_pages;

	plan = &workspace->hww_plan;
	bzero(plan, sizeof(*plan));
	plan->hwp_prefix = workspace->hww_prefix;
	plan->hwp_prefix_capacity = workspace->hww_prefix_capacity;
	plan->hwp_runs = workspace->hww_runs;
	plan->hwp_run_count = run_count;
	error = hibernate_writer_plan_assemble(plan, &workspace->hww_cb,
	    &workspace->hww_pcb);
	if (error != 0)
		return (error);

	attempt->ha_dst_intervals = workspace->hww_destination_intervals;
	attempt->ha_dst_count = run_count;
	atomic_thread_fence_rel();
	attempt->ha_dst_valid = true;
	return (0);
}

int
dump_for_hibernate(const struct hibernate_save_cb *hcb,
    const struct hibernate_save_pcb *hpcb, struct hibernate_attempt *attempt,
    const struct vm_phys_reservation *reservation,
    struct hibernate_writer_workspace *workspace, bool *image_committed)
{
	struct hibernate_provider_stream stream;
	struct hibernate_marker pending;
	struct dumperinfo *di;
	uint64_t image_offset, image_end, provider_end;
	int error;

	if (image_committed == NULL)
		return (EINVAL);
	*image_committed = false;
	if (attempt == NULL || reservation == NULL || workspace == NULL ||
	    attempt->ha_dumper == NULL)
		return (EINVAL);

	di = attempt->ha_dumper;
	if (di->dumper == NULL || di->dumper_read == NULL ||
	    di->dumper_flush == NULL || di->blocksize != DEV_BSIZE ||
	    di->kdcomp != NULL || di->kdcrypto != NULL ||
	    workspace->hww_io_buffer == NULL ||
	    workspace->hww_io_capacity < 2 * di->blocksize)
		return (EOPNOTSUPP);

	error = hibernate_writer_plan_live(hcb, hpcb, attempt, reservation,
	    workspace);
	if (error != 0)
		return (error);

	if (di->mediaoffset < 0 || di->mediasize <= 0 ||
	    __builtin_add_overflow((uint64_t)di->mediaoffset,
		(uint64_t)di->mediasize, &provider_end) ||
	    __builtin_add_overflow((uint64_t)di->mediaoffset,
		HIBERNATE_METADATA_SIZE, &image_offset) ||
	    __builtin_add_overflow(image_offset,
		workspace->hww_plan.hwp_image.hi_image_length, &image_end))
		return (EOVERFLOW);
	if (image_end > provider_end)
		return (ENOSPC);

	bzero(&stream, sizeof(stream));
	stream.hps_attempt = attempt;
	stream.hps_workspace = workspace;
	stream.hps_dumper = di;
	stream.hps_image_offset = image_offset;
	stream.hps_block_size = di->blocksize;
	stream.hps_crc_block = workspace->hww_io_buffer + di->blocksize;
	stream.hps_pending = &pending;
	bzero(workspace->hww_io_buffer, workspace->hww_io_capacity);

	bzero(&pending, sizeof(pending));
	pending.hm_magic = HIBERNATE_MARKER_MAGIC;
	pending.hm_version = HIBERNATE_MARKER_VERSION;
	pending.hm_state = HIBERNATE_MARKER_STATE_PENDING;
	pending.hm_image_offset = image_offset;
	pending.hm_image_length =
	    workspace->hww_plan.hwp_image.hi_image_length;

	++dumping;
	error = hibernate_commit_pending(attempt,
	    hibernate_provider_stream_image, &stream, &pending,
	    image_committed);
	--dumping;
	workspace->hww_image_committed = *image_committed;
	return (error);
}

int
dumpsys_generic(struct dumperinfo *di)
{
	static struct kerneldumpheader kdh;
	Elf_Ehdr ehdr;
	uint64_t dumpsize;
	off_t hdrgap;
	size_t hdrsz;
	int error;

#if MINIDUMP_PAGE_TRACKING == 1
	if (do_minidump)
		return (minidumpsys(di, false));
#endif

	bzero(&ehdr, sizeof(ehdr));
	ehdr.e_ident[EI_MAG0] = ELFMAG0;
	ehdr.e_ident[EI_MAG1] = ELFMAG1;
	ehdr.e_ident[EI_MAG2] = ELFMAG2;
	ehdr.e_ident[EI_MAG3] = ELFMAG3;
	ehdr.e_ident[EI_CLASS] = ELF_CLASS;
#if BYTE_ORDER == LITTLE_ENDIAN
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
#else
	ehdr.e_ident[EI_DATA] = ELFDATA2MSB;
#endif
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_STANDALONE;	/* XXX big picture? */
	ehdr.e_type = ET_CORE;
	ehdr.e_machine = EM_VALUE;
	ehdr.e_phoff = sizeof(ehdr);
	ehdr.e_flags = 0;
	ehdr.e_ehsize = sizeof(ehdr);
	ehdr.e_phentsize = sizeof(Elf_Phdr);
	ehdr.e_shentsize = sizeof(Elf_Shdr);

	dumpsys_pa_init();

	/* Calculate dump size. */
	dumpsize = 0L;
	ehdr.e_phnum = dumpsys_foreach_chunk(cb_size, &dumpsize) +
	    DUMPSYS_NUM_AUX_HDRS;
	hdrsz = ehdr.e_phoff + ehdr.e_phnum * ehdr.e_phentsize;
	fileofs = DEV_ALIGN(MD_ALIGN(hdrsz), di->blocksize);
	dumpsize += fileofs;
	hdrgap = fileofs - DEV_ALIGN(hdrsz, di->blocksize);

	dump_init_header(di, &kdh, KERNELDUMPMAGIC, KERNELDUMP_ARCH_VERSION,
	    dumpsize);

	error = dump_start(di, &kdh);
	if (error != 0)
		goto fail;

	printf("Dumping %ju MB (%d chunks)\n", (uintmax_t)dumpsize >> 20,
	    ehdr.e_phnum - DUMPSYS_NUM_AUX_HDRS);

	/* Dump ELF header */
	error = dumpsys_buf_write(di, (char*)&ehdr, sizeof(ehdr));
	if (error)
		goto fail;

	/* Dump program headers */
	error = dumpsys_foreach_chunk(cb_dumphdr, di);
	if (error < 0)
		goto fail;
	error = dumpsys_write_aux_headers(di);
	if (error < 0)
		goto fail;
	dumpsys_buf_flush(di);

	/*
	 * All headers are written using blocked I/O, so we know the
	 * current offset is (still) block aligned. Skip the alignement
	 * in the file to have the segment contents aligned at page
	 * boundary.
	 */
	error = dumpsys_buf_seek(di, (size_t)hdrgap);
	if (error)
		goto fail;

	/* Dump memory chunks. */
	error = dumpsys_foreach_chunk(dumpsys_cb_dumpdata, di);
	if (error < 0)
		goto fail;

	error = dump_finish(di, &kdh);
	if (error != 0)
		goto fail;

	printf("\nDump complete\n");
	return (0);

 fail:
	if (error < 0)
		error = -error;

	if (error == ECANCELED)
		printf("\nDump aborted\n");
	else if (error == E2BIG || error == ENOSPC)
		printf("\nDump failed. Partition too small.\n");
	else
		printf("\n** DUMP FAILED (ERROR %d) **\n", error);
	return (error);
}

#if MINIDUMP_PAGE_TRACKING == 1

/* Minidump progress bar */
static struct {
	const int min_per;
	const int max_per;
	bool visited;
} progress_track[10] = {
	{  0,  10, false},
	{ 10,  20, false},
	{ 20,  30, false},
	{ 30,  40, false},
	{ 40,  50, false},
	{ 50,  60, false},
	{ 60,  70, false},
	{ 70,  80, false},
	{ 80,  90, false},
	{ 90, 100, false}
};

static uint64_t dumpsys_pb_size;
static uint64_t dumpsys_pb_remaining;
static uint64_t dumpsys_pb_check;

/* Reset the progress bar for a dump of dumpsize. */
void
dumpsys_pb_init(uint64_t dumpsize)
{
	int i;

	dumpsys_pb_size = dumpsys_pb_remaining = dumpsize;
	dumpsys_pb_check = 0;

	for (i = 0; i < nitems(progress_track); i++)
		progress_track[i].visited = false;
}

/*
 * Update the progress according to the delta bytes that were written out.
 * Check and print the progress percentage.
 */
void
dumpsys_pb_progress(size_t delta)
{
	int sofar, i;

	dumpsys_pb_remaining -= delta;
	dumpsys_pb_check += delta;

	/*
	 * To save time while dumping, only loop through progress_track
	 * occasionally.
	 */
	if ((dumpsys_pb_check >> DUMPSYS_PB_CHECK_BITS) == 0)
		return;
	else
		dumpsys_pb_check &= (1 << DUMPSYS_PB_CHECK_BITS) - 1;

	sofar = 100 - ((dumpsys_pb_remaining * 100) / dumpsys_pb_size);
	for (i = 0; i < nitems(progress_track); i++) {
		if (sofar < progress_track[i].min_per ||
		    sofar > progress_track[i].max_per)
			continue;
		if (!progress_track[i].visited) {
			progress_track[i].visited = true;
			printf("..%d%%", sofar);
		}
		break;
	}
}

int
minidumpsys(struct dumperinfo *di, bool livedump)
{
	struct minidumpstate state;
	struct msgbuf mb_copy;
	char *msg_ptr;
	int error;

	if (livedump) {
		KASSERT(!dumping, ("live dump invoked from incorrect context"));

		/*
		 * Before invoking cpu_minidumpsys() on the live system, we
		 * must snapshot some required global state: the message
		 * buffer, and the page dump bitset. They may be modified at
		 * any moment, so for the sake of the live dump it is best to
		 * have an unchanging snapshot to work with. Both are included
		 * as part of the dump and consumed by userspace tools.
		 *
		 * Other global state important to the minidump code is the
		 * dump_avail array and the kernel's page tables, but snapshots
		 * are not taken of these. For one, dump_avail[] is expected
		 * not to change after boot. Snapshotting the kernel page
		 * tables would involve an additional walk, so this is avoided
		 * too.
		 *
		 * This means live dumps are best effort, and the result may or
		 * may not be usable; there are no guarantees about the
		 * consistency of the dump's contents. Any of the following
		 * (and likely more) may affect the live dump:
		 *
		 *  - Data may be modified, freed, or remapped during the
		 *    course of the dump, such that the contents written out
		 *    are partially or entirely unrecognizable. This means
		 *    valid references may point to destroyed/mangled objects,
		 *    and vice versa.
		 *
		 *  - The dumped context of any threads that ran during the
		 *    dump process may be unreliable.
		 *
		 *  - The set of kernel page tables included in the dump likely
		 *    won't correspond exactly to the copy of the dump bitset.
		 *    This means some pages will be dumped without any way to
		 *    locate them, and some pages may not have been dumped
		 *    despite appearing as if they should.
		 */
		msg_ptr = malloc(msgbufsize, M_TEMP, M_WAITOK);
		msgbuf_duplicate(msgbufp, &mb_copy, msg_ptr);
		state.msgbufp = &mb_copy;

		state.dump_bitset = BITSET_ALLOC(vm_page_dump_pages, M_TEMP,
		    M_WAITOK);
		BIT_COPY_STORE_REL(vm_page_dump_pages, vm_page_dump,
		    state.dump_bitset);
	} else {
		KASSERT(dumping, ("minidump invoked outside of doadump()"));

		/* Use the globals. */
		state.msgbufp = msgbufp;
		state.dump_bitset = vm_page_dump;
	}

	error = cpu_minidumpsys(di, &state);
	if (livedump) {
		free(msg_ptr, M_TEMP);
		BITSET_FREE(state.dump_bitset, M_TEMP);
	}

	return (error);
}
#endif /* MINIDUMP_PAGE_TRACKING == 1 */

#endif /* !_HIBERNATE_DUMP_EXTENT_TEST */
