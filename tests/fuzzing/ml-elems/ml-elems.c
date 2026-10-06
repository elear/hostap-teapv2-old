/*
 * Multi-Link element parsing - fuzzer
 * Copyright (c) 2026, Louis Kotze <loukot@gmail.com>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "common/ieee802_11_common.h"
#include "common/ieee802_11_defs.h"
#include "common/defs.h"
#include "../fuzzer-common.h"


/*
 * Drive the per-STA profile parsers the way the callers in bss.c and events.c
 * do: the buffer starts at the Multi-Link Control field, not at the element
 * header. Both parsers may defragment subelements in place, so each call gets
 * its own copy.
 */
static void fuzz_link_profile(const u8 *mle, size_t mle_len)
{
	struct ieee802_11_elems elems;
	struct wpabuf *mlbuf;
	u8 link_id;

	if (!mle || !mle_len)
		return;

	for (link_id = 0; link_id < MAX_NUM_MLD_LINKS; link_id++) {
		mlbuf = ieee802_11_defrag(mle, mle_len, true);
		if (!mlbuf)
			return;
		os_memset(&elems, 0, sizeof(elems));
		ieee802_11_parse_link_assoc_req(&elems, mlbuf, link_id, 1);
		wpabuf_free(mlbuf);

		mlbuf = ieee802_11_defrag(mle, mle_len, true);
		if (!mlbuf)
			return;
		os_memset(&elems, 0, sizeof(elems));
		ieee802_11_parse_link_assoc_resp(&elems, mlbuf, link_id, 1);
		wpabuf_free(mlbuf);
	}

	/* parent_subelem must point inside mlbuf and, as every in-tree caller
	 * guarantees by looping on "len > 2", must have a readable two octet
	 * subelement header. Passing anything shorter breaks the callee's
	 * contract and would only report a defect in this harness. */
	if (mle_len >= 2) {
		mlbuf = ieee802_11_defrag(mle, mle_len, true);
		if (mlbuf) {
			size_t defrag_len = 0;

			ieee802_11_defrag_mle_subelem(mlbuf, wpabuf_head(mlbuf),
						      &defrag_len);
			wpabuf_free(mlbuf);
		}
	}
}


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ieee802_11_elems elems;
	struct wpabuf *buf;
	u8 type;

	wpa_fuzzer_set_debug_level();

	/* Full element parsing; dispatches to the Multi-Link element handling
	 * and to element fragment reassembly. */
	ieee802_11_parse_elems(data, size, &elems, 1);

	/* Each Multi-Link element variant the parser recognised, handed on in
	 * the same shape the real callers use. */
	fuzz_link_profile(elems.basic_mle, elems.basic_mle_len);
	fuzz_link_profile(elems.probe_req_mle, elems.probe_req_mle_len);
	fuzz_link_profile(elems.reconf_mle, elems.reconf_mle_len);
	fuzz_link_profile(elems.tdls_mle, elems.tdls_mle_len);
	fuzz_link_profile(elems.prior_access_mle, elems.prior_access_mle_len);

	/* Basic Multi-Link element accessors, both on the element payload the
	 * parser found and on the raw input, so the short-buffer rejection
	 * paths are covered too. */
	if (elems.basic_mle) {
		get_basic_mle_mld_addr(elems.basic_mle, elems.basic_mle_len);
		get_basic_mle_eml_capa(elems.basic_mle, elems.basic_mle_len);
		get_basic_mle_link_id(elems.basic_mle, elems.basic_mle_len);
	}
	get_basic_mle_mld_addr(data, size);
	get_basic_mle_eml_capa(data, size);
	get_basic_mle_link_id(data, size);

	for (type = 0; type < 8; type++)
		get_ml_ie(data, size, type);

	/* Element defragmentation, both element and extended-element forms. */
	buf = ieee802_11_defrag(data, size, true);
	if (buf) {
		/* Also drive subelement defragmentation straight off the input,
		 * not only via a Multi-Link element the parser recognised. */
		if (wpabuf_len(buf) >= 2) {
			size_t defrag_len = 0;

			ieee802_11_defrag_mle_subelem(buf, wpabuf_head(buf),
						      &defrag_len);
		}
		wpabuf_free(buf);
	}
	buf = ieee802_11_defrag(data, size, false);
	wpabuf_free(buf);

	return 0;
}
