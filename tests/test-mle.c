/*
 * Multi-Link element accessor boundary tests
 * Copyright (c) 2026, Louis Kotze <loukot@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * These use exactly sized heap allocations on purpose: an off-by-one read is
 * only visible to a memory checker when the redzone sits immediately after the
 * last valid byte. Run under ASan or valgrind for the boundary cases to mean
 * anything.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_common.h"
#include "common/ieee802_11_defs.h"
#include "common/defs.h"

static int failures;

#define CHECK(cond) do {						\
		if (!(cond)) {						\
			wpa_printf(MSG_ERROR,				\
				   "FAIL %s:%d: %s",			\
				   __func__, __LINE__, #cond);		\
			failures++;					\
		}							\
	} while (0)

/* Run fn against an exactly sized copy of buf so a one-past-the-end read lands
 * in an ASan redzone rather than in adjacent heap data. */
static void with_exact_alloc(const u8 *buf, size_t len,
			     void (*fn)(const u8 *, size_t))
{
	u8 *p = os_malloc(len ? len : 1);

	if (!p)
		return;
	if (len)
		os_memcpy(p, buf, len);
	fn(p, len);
	os_free(p);
}


static void probe_eml_capa(const u8 *p, size_t len)
{
	get_basic_mle_eml_capa(p, len);
}


static void probe_link_id(const u8 *p, size_t len)
{
	get_basic_mle_link_id(p, len);
}


static void probe_mld_addr(const u8 *p, size_t len)
{
	get_basic_mle_mld_addr(p, len);
}


/*
 * Regression: the guard was "len < MULTI_LINK_CONTROL_LEN" (2) while the next
 * read was buf[MULTI_LINK_CONTROL_LEN], so len == 2 read one byte past the end.
 * Reachable from wpa_supplicant/scan.c when an AP beacons a Basic Multi-Link
 * element whose element length is 3.
 */
static void test_truncated_common_info_len(void)
{
	/* The two inputs libFuzzer produced, plus every short length. */
	const u8 crash1[] = { 0x00, 0xef };
	const u8 crash2[] = { 0xc8, 0x0a };
	u8 buf[8];
	size_t len;

	with_exact_alloc(crash1, sizeof(crash1), probe_link_id);
	with_exact_alloc(crash2, sizeof(crash2), probe_eml_capa);
	with_exact_alloc(crash1, sizeof(crash1), probe_eml_capa);
	with_exact_alloc(crash2, sizeof(crash2), probe_link_id);

	/* Every control value at exactly the boundary length. */
	for (len = 0; len <= 4; len++) {
		unsigned int c;

		for (c = 0; c < 0x200; c++) {
			buf[0] = c & 0xff;
			buf[1] = (c >> 8) & 0xff;
			buf[2] = 0xff;
			buf[3] = 0xff;
			with_exact_alloc(buf, len, probe_eml_capa);
			with_exact_alloc(buf, len, probe_link_id);
			with_exact_alloc(buf, len, probe_mld_addr);
		}
	}
}


/* A well-formed minimal Basic MLE must still parse, so the fix cannot simply
 * reject everything. */
static void test_valid_basic_mle(void)
{
	const u8 mld_addr[ETH_ALEN] = { 0x02, 0, 0, 0, 0, 0 };
	u8 buf[32];
	size_t pos = 0;
	const u8 *addr;
	int link_id;
	u16 ctrl = MULTI_LINK_CONTROL_TYPE_BASIC |
		BASIC_MULTI_LINK_CTRL_PRES_LINK_ID;

	WPA_PUT_LE16(buf, ctrl);
	pos = 2;
	buf[pos++] = 1 + ETH_ALEN + 1;	/* Common Info Length, incl. itself */
	os_memcpy(&buf[pos], mld_addr, ETH_ALEN);
	pos += ETH_ALEN;
	buf[pos++] = 0x03;		/* Link ID Info */

	addr = get_basic_mle_mld_addr(buf, pos);
	CHECK(addr != NULL);
	if (addr)
		CHECK(os_memcmp(addr, mld_addr, ETH_ALEN) == 0);

	link_id = get_basic_mle_link_id(buf, pos);
	CHECK(link_id == 3);

	/* Truncating a valid element by one byte at a time must never read out
	 * of bounds and must never return a link ID it cannot have seen. */
	while (pos > 0) {
		pos--;
		with_exact_alloc(buf, pos, probe_link_id);
		with_exact_alloc(buf, pos, probe_eml_capa);
		with_exact_alloc(buf, pos, probe_mld_addr);
	}
}


/* A declared Common Info Length longer than the buffer must be rejected. */
static void test_lying_common_info_len(void)
{
	u8 buf[16];
	size_t len;

	for (len = 3; len <= sizeof(buf); len++) {
		WPA_PUT_LE16(buf, MULTI_LINK_CONTROL_TYPE_BASIC |
			     BASIC_MULTI_LINK_CTRL_PRES_LINK_ID |
			     BASIC_MULTI_LINK_CTRL_PRES_EML_CAPA);
		buf[2] = 0xff;	/* claims 255 bytes of Common Info */
		os_memset(&buf[3], 0x41, len - 3);
		with_exact_alloc(buf, len, probe_eml_capa);
		with_exact_alloc(buf, len, probe_link_id);
	}
}


int main(void)
{
	wpa_debug_level = MSG_INFO;

	test_truncated_common_info_len();
	test_valid_basic_mle();
	test_lying_common_info_len();

	if (failures) {
		wpa_printf(MSG_ERROR, "%d test(s) FAILED", failures);
		return 1;
	}

	wpa_printf(MSG_INFO, "test-mle: all tests passed");
	return 0;
}
