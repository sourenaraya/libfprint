/*
 * Synaptics Tudor Match-In-Sensor driver for libfprint
 *
 * TUDOR host-partition pairing-record builder ("W" form) — see preboot_record.h.
 *
 * Self-contained (glib + OpenSSL only) so the byte-exact output can be checked
 * offline against a captured Windows pairing record. OpenSSL contexts are
 * freed manually (no g_autoptr) so this builds against any OpenSSL 3.x.
 */

#include "preboot_record.h"

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define PREBOOT_ERROR (g_quark_from_static_string ("preboot-record-error"))

/* COMMON: the fixed 32B salt for the record KDF (from the decoded firmware). */
static const guint8 COMMON[32] = {
  0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a,
  0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19,
  0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38,
  0x38, 0x46, 0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33
};

#define PREBOOT_MAGIC        1u
#define PREBOOT_MAC_LEN      32
#define PREBOOT_SHA256_LEN   32
#define PREBOOT_IV_LEN       16
#define PREBOOT_HDR_LEN      16
#define PREBOOT_CONTAINER_LEN 4096

static void
put_u16_le (guint8 *p, guint16 v)
{
  p[0] = (guint8) (v & 0xff);
  p[1] = (guint8) (v >> 8);
}

static void
put_u32_le (guint8 *p, guint32 v)
{
  p[0] = (guint8) (v & 0xff);
  p[1] = (guint8) (v >> 8);
  p[2] = (guint8) (v >> 16);
  p[3] = (guint8) (v >> 24);
}

static guint16
get_u16_le (const guint8 *p)
{
  return (guint16) (p[0] | (p[1] << 8));
}

static guint32
get_u32_le (const guint8 *p)
{
  return (guint32) p[0] | ((guint32) p[1] << 8) |
         ((guint32) p[2] << 16) | ((guint32) p[3] << 24);
}

static gboolean
sha256 (const guint8 *data, gsize data_len, guint8 out[PREBOOT_SHA256_LEN])
{
  EVP_MD_CTX *mctx = EVP_MD_CTX_new ();
  guint8 tmp[EVP_MAX_MD_SIZE];
  unsigned int tmp_len = 0;
  gboolean ok;

  if (mctx == NULL)
    return FALSE;

  ok = EVP_DigestInit_ex (mctx, EVP_sha256 (), NULL) == 1 &&
       EVP_DigestUpdate (mctx, data, data_len) == 1 &&
       EVP_DigestFinal_ex (mctx, tmp, &tmp_len) == 1;
  EVP_MD_CTX_free (mctx);

  if (!ok || tmp_len != PREBOOT_SHA256_LEN)
    return FALSE;
  memcpy (out, tmp, PREBOOT_SHA256_LEN);
  return TRUE;
}

static gboolean
hmac_sha256 (const guint8 *key, gsize key_len,
             const guint8 *data, gsize data_len,
             guint8 out[PREBOOT_SHA256_LEN], GError **error)
{
  EVP_MAC *mac = EVP_MAC_fetch (NULL, "HMAC", NULL);
  EVP_MAC_CTX *mctx = mac ? EVP_MAC_CTX_new (mac) : NULL;
  guint8 tmp[EVP_MAX_MD_SIZE];
  size_t tmp_len = 0;
  OSSL_PARAM params[2];
  gboolean ok;

  if (mac == NULL || mctx == NULL)
    {
      if (mac)
        EVP_MAC_free (mac);
      g_set_error (error, PREBOOT_ERROR, 0, "HMAC fetch failed");
      return FALSE;
    }

  /* OSSL_PARAM_construct_utf8_string takes a non-const buffer but only reads
   * it (the value is copied); the literal is safe to cast. */
  params[0] =
      OSSL_PARAM_construct_utf8_string (OSSL_MAC_PARAM_DIGEST,
                                        (char *) "SHA256", 0);
  params[1] = OSSL_PARAM_construct_end ();

  ok = EVP_MAC_init (mctx, key, key_len, params) &&
       EVP_MAC_update (mctx, data, data_len) &&
       EVP_MAC_final (mctx, tmp, &tmp_len, sizeof (tmp));
  EVP_MAC_CTX_free (mctx);
  EVP_MAC_free (mac);

  if (!ok)
    {
      g_set_error (error, PREBOOT_ERROR, 0, "HMAC-SHA256 failed: %s",
                   ERR_error_string (ERR_get_error (), NULL));
      return FALSE;
    }
  if (tmp_len != PREBOOT_SHA256_LEN)
    {
      g_set_error (error, PREBOOT_ERROR, 0, "HMAC-SHA256: unexpected digest length");
      return FALSE;
    }

  memcpy (out, tmp, PREBOOT_SHA256_LEN);
  return TRUE;
}

/* KDF: prk = HMAC-SHA256(COMMON, label||key2); out = HMAC-SHA256(COMMON, prk||label||key2). */
static gboolean
kdf_derive (const char *label, const guint8 *key2, gsize key2_len,
            guint8 out[32], GError **error)
{
  gsize label_len = strlen (label);
  g_autofree guint8 *msg1 = g_malloc (label_len + key2_len);
  g_autofree guint8 *msg2 = g_malloc (32 + label_len + key2_len);
  guint8 prk[32];

  memcpy (msg1, label, label_len);
  memcpy (msg1 + label_len, key2, key2_len);
  if (!hmac_sha256 (COMMON, 32, msg1, label_len + key2_len, prk, error))
    return FALSE;

  memcpy (msg2, prk, 32);
  memcpy (msg2 + 32, label, label_len);
  memcpy (msg2 + 32 + label_len, key2, key2_len);
  return hmac_sha256 (COMMON, 32, msg2, 32 + label_len + key2_len, out, error);
}

static gboolean
aes256_cbc (gboolean encrypt, const guint8 key[32], const guint8 iv[16],
            const guint8 *in, gsize in_len,
            guint8 **out, gsize *out_len, GError **error)
{
  EVP_CIPHER *cipher = EVP_CIPHER_fetch (NULL, "AES-256-CBC", NULL);
  EVP_CIPHER_CTX *cctx = cipher ? EVP_CIPHER_CTX_new () : NULL;
  guint8 *buf = NULL;
  int len1 = 0, len2 = 0;

  if (cipher == NULL || cctx == NULL)
    {
      if (cipher)
        EVP_CIPHER_free (cipher);
      g_set_error (error, PREBOOT_ERROR, 0, "AES-256-CBC: fetch/context failed");
      return FALSE;
    }

  buf = g_malloc (in_len + EVP_CIPHER_get_block_size (cipher));
  if (encrypt)
    {
      if (EVP_EncryptInit_ex2 (cctx, cipher, key, iv, NULL) != 1 ||
          EVP_EncryptUpdate (cctx, buf, &len1, in, (int) in_len) != 1 ||
          EVP_EncryptFinal_ex (cctx, buf + len1, &len2) != 1)
        goto err;
    }
  else
    {
      if (EVP_DecryptInit_ex2 (cctx, cipher, key, iv, NULL) != 1 ||
          EVP_DecryptUpdate (cctx, buf, &len1, in, (int) in_len) != 1 ||
          EVP_DecryptFinal_ex (cctx, buf + len1, &len2) != 1)
        goto err;
    }

  EVP_CIPHER_CTX_free (cctx);
  EVP_CIPHER_free (cipher);
  *out = buf;
  *out_len = (gsize) (len1 + len2);
  return TRUE;

err:
  g_free (buf);
  EVP_CIPHER_CTX_free (cctx);
  EVP_CIPHER_free (cipher);
  g_set_error (error, PREBOOT_ERROR, 0, "AES-256-CBC %s failed: %s",
               encrypt ? "encrypt" : "decrypt",
               ERR_error_string (ERR_get_error (), NULL));
  return FALSE;
}

/* append one inner TLV: [u16 tag][u32 len][value] */
static void
tlv_write (guint8 **p, guint16 tag, const guint8 *val, gsize val_len)
{
  put_u16_le (*p, tag);
  put_u32_le (*p + 2, (guint32) val_len);
  memcpy (*p + 6, val, val_len);
  *p += 6 + val_len;
}

gboolean
preboot_record_build (
    const guint8 *host_scalar, gsize host_scalar_len,
    const guint8 *host_cert, gsize host_cert_len,
    const guint8 *sec_blob, gsize sec_blob_len,
    const guint8 *sensor_cert, gsize sensor_cert_len,
    const guint8 *key2, gsize key2_len,
    const guint8 iv[16],
    guint8 **out_record, gsize *out_len, GError **error)
{
  gsize container_len = 6 * 5 + host_scalar_len + host_cert_len +
                        sec_blob_len + sensor_cert_len + 2;
  g_autofree guint8 *container = g_malloc (container_len);
  guint8 *p = container;
  guint8 aes_key[32], mac_key[32];
  guint8 *ct = NULL;
  gsize ct_len = 0;
  gsize record_len;
  guint8 *record;

  /* inner container, fixed order: tag2, tag1, tag4, tag3, tag0 terminator */
  tlv_write (&p, 2, host_scalar, host_scalar_len);
  tlv_write (&p, 1, host_cert, host_cert_len);
  tlv_write (&p, 4, sec_blob, sec_blob_len);
  tlv_write (&p, 3, sensor_cert, sensor_cert_len);
  put_u16_le (p, 0);
  put_u32_le (p + 2, 2);
  p[6] = 0;
  p[7] = 0;
  p += 8;
  g_assert (p - container == (gssize) container_len);

  if (!kdf_derive ("PD_ENC", key2, key2_len, aes_key, error) ||
      !kdf_derive ("PD_SIGN", key2, key2_len, mac_key, error))
    return FALSE;

  if (!aes256_cbc (TRUE, aes_key, iv, container, container_len, &ct, &ct_len, error))
    return FALSE;

  record_len = PREBOOT_HDR_LEN + PREBOOT_IV_LEN + ct_len + PREBOOT_MAC_LEN;
  record = g_malloc (record_len);
  put_u32_le (record + 0, PREBOOT_MAGIC);
  put_u32_le (record + 4, 0);
  put_u32_le (record + 8, (guint32) (ct_len + PREBOOT_IV_LEN)); /* ct_len, IV-inclusive */
  put_u32_le (record + 12, PREBOOT_MAC_LEN);
  memcpy (record + PREBOOT_HDR_LEN, iv, PREBOOT_IV_LEN);
  memcpy (record + PREBOOT_HDR_LEN + PREBOOT_IV_LEN, ct, ct_len);
  g_free (ct);

  /* MAC over hdr | prefix | IV | ct */
  if (!hmac_sha256 (mac_key, 32, record,
                    PREBOOT_HDR_LEN + PREBOOT_IV_LEN + ct_len,
                    record + PREBOOT_HDR_LEN + PREBOOT_IV_LEN + ct_len, error))
    {
      g_free (record);
      return FALSE;
    }

  *out_record = record;
  *out_len = record_len;
  return TRUE;
}

gboolean
preboot_record_extract_sec_blob (
    const guint8 *record, gsize record_len,
    const guint8 *key2, gsize key2_len,
    guint8 **out_sec, gsize *out_sec_len, GError **error)
{
  guint32 magic, prefix_len, ct_len_field, mac_len;
  gsize ct_len, iv_off;
  const guint8 *iv, *ct, *mac;
  guint8 aes_key[32], mac_key[32];
  guint8 mac_calc[PREBOOT_SHA256_LEN];
  guint8 *pt = NULL;
  gsize pt_len = 0, o = 0;

  if (record_len < PREBOOT_HDR_LEN + PREBOOT_IV_LEN + PREBOOT_MAC_LEN)
    return FALSE;

  magic = get_u32_le (record + 0);
  prefix_len = get_u32_le (record + 4);
  ct_len_field = get_u32_le (record + 8);
  mac_len = get_u32_le (record + 12);
  if (magic != PREBOOT_MAGIC || mac_len != PREBOOT_MAC_LEN ||
      ct_len_field <= PREBOOT_IV_LEN)
    return FALSE;

  ct_len = ct_len_field - PREBOOT_IV_LEN;
  iv_off = PREBOOT_HDR_LEN + prefix_len;
  if (iv_off + PREBOOT_IV_LEN + ct_len + PREBOOT_MAC_LEN > record_len)
    return FALSE;

  iv = record + iv_off;
  ct = record + iv_off + PREBOOT_IV_LEN;
  mac = record + iv_off + PREBOOT_IV_LEN + ct_len;

  if (!kdf_derive ("PD_ENC", key2, key2_len, aes_key, error) ||
      !kdf_derive ("PD_SIGN", key2, key2_len, mac_key, error))
    return FALSE;

  /* MAC must verify under key2 — distinguishes a W-form record from the
   * CTR/vendor fallback. */
  if (!hmac_sha256 (mac_key, 32, record, iv_off + PREBOOT_IV_LEN + ct_len, mac_calc, error))
    return FALSE;
  if (memcmp (mac_calc, mac, PREBOOT_MAC_LEN) != 0)
    return FALSE; /* not W-form (wrong key2, or the CTR fallback) */

  if (!aes256_cbc (FALSE, aes_key, iv, ct, ct_len, &pt, &pt_len, error))
    return FALSE;

  /* scan inner TLVs for tag4 */
  while (o + 6 <= pt_len)
    {
      guint16 tag = get_u16_le (pt + o);
      guint32 vlen = get_u32_le (pt + o + 2);
      if (tag == 0)
        break;
      if (o + 6 + vlen > pt_len)
        {
          g_free (pt);
          g_set_error (error, PREBOOT_ERROR, 0, "malformed inner container");
          return FALSE;
        }
      if (tag == 4)
        {
          *out_sec = g_memdup2 (pt + o + 6, vlen);
          *out_sec_len = vlen;
          g_free (pt);
          return TRUE;
        }
      o += 6 + vlen;
    }

  g_free (pt);
  g_set_error (error, PREBOOT_ERROR, 0, "no tag4 (SEC blob) in record");
  return FALSE;
}

guint8 *
preboot_container_build (
    const guint8 version[4],
    const guint8 *record, gsize record_len,
    gsize *out_len)
{
  guint8 *container = g_malloc (PREBOOT_CONTAINER_LEN);
  guint8 vsha[PREBOOT_SHA256_LEN], rsha[PREBOOT_SHA256_LEN];

  memset (container, 0xff, PREBOOT_CONTAINER_LEN);

  /* tag1 (version) @0: [u16 tag][u16 len][32B sha256][value] */
  put_u16_le (container + 0, 1);
  put_u16_le (container + 2, 4);
  sha256 (version, 4, vsha);
  memcpy (container + 4, vsha, PREBOOT_SHA256_LEN);
  memcpy (container + 36, version, 4);

  /* tag2 (record) @40 */
  put_u16_le (container + 40, 2);
  put_u16_le (container + 42, (guint16) record_len);
  sha256 (record, record_len, rsha);
  memcpy (container + 44, rsha, PREBOOT_SHA256_LEN);
  memcpy (container + 76, record, record_len);

  *out_len = PREBOOT_CONTAINER_LEN;
  return container;
}

/* Read one DMI field: <dmi_dir>/<name>, trimmed of trailing whitespace. */
static gboolean
read_dmi_field (const char *dmi_dir, const char *name,
                guint8 **out, gsize *out_len, GError **error)
{
  g_autofree gchar *path = g_build_filename (dmi_dir, name, NULL);
  g_autofree gchar *content = NULL;
  gsize len = 0;

  if (!g_file_get_contents (path, &content, &len, error))
    return FALSE;
  while (len > 0 && (content[len - 1] == '\n' || content[len - 1] == '\r'))
    len--;
  if (len == 0)
    {
      g_set_error (error, PREBOOT_ERROR, 0, "DMI field %s is empty", name);
      return FALSE;
    }
  *out = g_memdup2 (content, len);
  *out_len = len;
  return TRUE;
}

gboolean
preboot_synthesize_key2 (
    const char *dmi_dir, guint8 **out_key2, gsize *out_len, GError **error)
{
  g_autofree guint8 *product = NULL, *serial = NULL;
  gsize product_len = 0, serial_len = 0;
  guint8 *key2;
  gsize key2_len;

  if (!read_dmi_field (dmi_dir, "product_name", &product, &product_len, error) ||
      !read_dmi_field (dmi_dir, "product_serial", &serial, &serial_len, error))
    return FALSE;

  /* key2_stable = Product Name + NUL + Serial Number + NUL (the EAIA 0xC0 slice). */
  key2_len = product_len + 1 + serial_len + 1;
  key2 = g_malloc (key2_len);
  memcpy (key2, product, product_len);
  key2[product_len] = 0;
  memcpy (key2 + product_len + 1, serial, serial_len);
  key2[product_len + 1 + serial_len] = 0;

  if (key2_len != PREBOOT_KEY2_LEN)
    {
      g_free (key2);
      g_set_error (error, PREBOOT_ERROR, 0,
                   "key2 from DMI is %zu bytes (product_name %zu, product_serial %zu), expected %d",
                   key2_len, product_len, serial_len, PREBOOT_KEY2_LEN);
      return FALSE;
    }

  *out_key2 = key2;
  *out_len = key2_len;
  return TRUE;
}
