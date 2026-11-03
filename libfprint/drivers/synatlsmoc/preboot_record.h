#pragma once

#include <glib.h>

/* Length of key2_stable (the EAIA 0xC0 slice): fixed 20 bytes on this
 * hardware (SMBIOS Product Name + NUL + Serial Number + NUL). */
#define PREBOOT_KEY2_LEN 20

/*
 * TUDOR host-partition pairing-record builder ("W" form).
 *
 * Emits the record form the UEFI pre-boot .efi accepts:
 *   record   = [16B hdr][prefix][16B IV][ct][32B HMAC-SHA256]
 *   hdr      = u32 magic(1) | u32 prefix_len(0) | u32 ct_len (IV-inclusive) | u32 mac_len(32)
 *   ct       = AES-256-CBC + PKCS7 over the inner container
 *   keys     = KDF(COMMON, "PD_ENC"|"PD_SIGN", key2)
 *   MAC      = HMAC-SHA256(mac_key, hdr | prefix | IV | ct)
 *   inner    = [u16 tag][u32 len][value] TLVs, fixed order 2,1,4,3,0
 *   outer    = 4096B: tag1 (4B version) + tag2 (record) + 0xFF fill,
 *               each outer tag = [u16 tag][u16 len][32B sha256][value]
 *
 * key2 (key2_stable, 20B) is supplied by the caller — never hardcoded here.
 */

/* Build a record. host_scalar (tag2, 32B) must be the little-endian P-256
 * private scalar matching host_cert (tag1). sec_blob (tag4) is the 420B
 * sensor-static SEC blob (retained from the existing record). iv (16B) is
 * caller-supplied (generate with RAND_bytes). */
gboolean preboot_record_build (
    const guint8 *host_scalar, gsize host_scalar_len,
    const guint8 *host_cert, gsize host_cert_len,
    const guint8 *sec_blob, gsize sec_blob_len,
    const guint8 *sensor_cert, gsize sensor_cert_len,
    const guint8 *key2, gsize key2_len,
    const guint8 iv[16],
    guint8 **out_record, gsize *out_len, GError **error);

/* MAC-verify + decrypt an existing "W"-form record under key2 and return its
 * tag4 (the 420B SEC blob) for read-modify-write. Returns FALSE (no error set)
 * when the record is not in W form (e.g. the CTR/vendor fallback), or on a
 * genuine parse/crypto failure (error set). */
gboolean preboot_record_extract_sec_blob (
    const guint8 *record, gsize record_len,
    const guint8 *key2, gsize key2_len,
    guint8 **out_sec, gsize *out_sec_len, GError **error);

/* Build the outer 4096B container wrapping a 1360B record. version is the
 * 4-byte (u32 LE) record version (1 => {1,0,0,0}); retained from the existing
 * container on a read-modify-write. */
guint8 *preboot_container_build (
    const guint8 version[4],
    const guint8 *record, gsize record_len,
    gsize *out_len);

/*
 * Reconstruct key2_stable at runtime from SMBIOS — no shipped key file, no
 * hardcoded key (key2_stable is the EAIA 0xC0 slice, which SMBIOS exports as
 * the machine's Type 1 fields). key2 = /sys/class/dmi/id/product_name + 0x00 +
 * /sys/class/dmi/id/product_serial + 0x00; product_serial is root-only, so the
 * caller must run as root (fprintd does).
 *
 * dmi_dir holds the kernel DMI exports (default "/sys/class/dmi/id"); the
 * kernel leaves product_serial root-only, so the caller must run as root
 * (fprintd does — see fprintd.service). Returns FALSE with a set error if a
 * field is missing/empty or the result is not PREBOOT_KEY2_LEN bytes. Pass a
 * temp dir to unit-test without DMI access.
 */
gboolean preboot_synthesize_key2 (
    const char *dmi_dir, guint8 **out_key2, gsize *out_len, GError **error);
