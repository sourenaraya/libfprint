/*
 * Synaptics Tudor Match-In-Sensor driver for libfprint
 *
 * Copyright (c) 2024 Francesco Circhetta, Vojtěch Pluskal
 *
 * Some parts are based on:
 *    - work of Popax21, see: https://github.com/Popax21/synaTudor/tree/rev
 *    - egismoc libfprint driver by Joshua Grisham, see egismoc.c,
 *       of which portions are from elanmoc libfprint driver (C) 2021 Elan
 *       Microelectronic
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */


#define FP_COMPONENT "synamoc-Pairing"

#include <glib.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>

#include "fpi-byte-writer.h"
#include "fpi-device.h"
#include "fpi-log.h"
#include "pairing.h"
#include "tls_session.h"
#include "utils.h"

static gboolean
generate_hs_priv_key (EVP_PKEY **hs_privkey, GError **error)
{
  guint8 secret[] = { 0x71, 0x7c, 0xd7, 0x2d, 0x09, 0x62, 0xbc, 0x4a,
                      0x28, 0x46, 0x13, 0x8d, 0xbb, 0x2c, 0x24, 0x19 };
  guint8 seed[] = { 0x25, 0x12, 0xa7, 0x64, 0x07, 0x06, 0x5f, 0x38, 0x38,
                    0x46, 0x13, 0x9d, 0x4b, 0xec, 0x20, 0x33, 0xaa, 0xaa };
  const gchar *label = "HS_KEY_PAIR_GEN";

  guint8 privkey_k[ECC_KEY_SIZE];
  if (!tls_prf (secret, sizeof (secret), label, strlen (label), seed, sizeof (seed),
                privkey_k, ECC_KEY_SIZE, SN_sha256, error))
    {
      return FALSE;
    }

  /* output is in little-endian, OpenSSL expects big-endian */
  reverse_array (privkey_k, ECC_KEY_SIZE);

#ifdef DEBUG_SSL
  /* NOTE: expected result (HS_KEY_PAIR_GEN), then converted to big-endian as
   * expected by OpenSSL
   * guint8 k[ECC_KEY_SIZE] = {0xe8, 0xa2, 0xa2, 0xb6, 0x65, 0x62, 0x54, 0xd6,
   * 0xac, 0xb0, 0xef, 0x47, 0x9c, 0xae, 0x41, 0x40, 0xc7, 0xe8, 0xe2, 0x60,
   * 0xdb, 0x3f, 0x64, 0x2e, 0x35, 0xd4, 0x09, 0x9c, 0x01, 0xb3, 0x6a, 0x86};
   */
  g_autofree char *privkey_k_str = bin2hex (privkey_k, ECC_KEY_SIZE);
  fp_dbg ("Generated hs privkey k param: %s", privkey_k_str);
#endif

  g_autoptr (OSSL_PARAM_BLD) param_bld = OSSL_PARAM_BLD_new ();
  g_autoptr (BIGNUM) k_bn = BN_bin2bn (privkey_k, ECC_KEY_SIZE, NULL);

  if (param_bld == NULL ||
      !OSSL_PARAM_BLD_push_utf8_string (param_bld, "group", "prime256v1", 0) ||
      !OSSL_PARAM_BLD_push_BN (param_bld, "priv", k_bn))
    {
      g_propagate_error (error,
                         set_and_report_error (
                             FP_DEVICE_ERROR_GENERAL,
                             "Failed to generate OSSL builder for private key: %s",
                             ERR_error_string (ERR_get_error (), NULL)));
      return FALSE;
    }

  g_autoptr (OSSL_PARAM) params = OSSL_PARAM_BLD_to_param (param_bld);
  g_autoptr (EVP_PKEY_CTX) ctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);

  if (ctx == NULL || params == NULL || !EVP_PKEY_fromdata_init (ctx) ||
      !EVP_PKEY_fromdata (ctx, hs_privkey, EVP_PKEY_KEYPAIR, params))
    {
      g_propagate_error (
          error, set_and_report_error (FP_DEVICE_ERROR_GENERAL,
                                       "Failed to load hs private key: %s",
                                       ERR_error_string (ERR_get_error (), NULL)));
      return FALSE;
    }

  return TRUE;
}

gboolean
create_host_certificate (EVP_PKEY *server_key,
                         guint8 **host_certificate_bytes,
                         GError **error)
{
  *host_certificate_bytes = g_malloc (CERTIFICATE_SIZE);

  // get x public key coordinate
  g_autoptr (BIGNUM) x_bn = BN_new ();
  if (EVP_PKEY_get_bn_param (server_key, OSSL_PKEY_PARAM_EC_PUB_X, &x_bn) != 1)
    {
      g_propagate_error (
          error, set_and_report_error (
                     FP_DEVICE_ERROR_GENERAL,
                     "OpenSSL error while getting x coordinate of public key: %s",
                     ERR_error_string (ERR_get_error (), NULL)));
      return FALSE;
    }

  gsize x_bytes_size = BN_num_bytes (x_bn);
  g_autofree guint8 *x_bytes = g_malloc (x_bytes_size);
  const int x_len = BN_bn2bin (x_bn, x_bytes);
  g_assert (x_len == x_bytes_size);

  // get y public key coordinate
  g_autoptr (BIGNUM) y_bn = BN_new ();
  if (EVP_PKEY_get_bn_param (server_key, OSSL_PKEY_PARAM_EC_PUB_Y, &y_bn) != 1)
    {
      g_propagate_error (
          error, set_and_report_error (
                     FP_DEVICE_ERROR_GENERAL,
                     "OpenSSL error while getting y coordinate of public key: %s",
                     ERR_error_string (ERR_get_error (), NULL)));
      return FALSE;
    }
  gsize y_bytes_size = BN_num_bytes (y_bn);
  g_autofree guint8 *y_bytes = g_malloc (y_bytes_size);
  const int y_len = BN_bn2bin (y_bn, y_bytes);
  g_assert (y_len == y_bytes_size);

  FpiByteWriter writer;
  fpi_byte_writer_init_with_data (&writer, *host_certificate_bytes,
                                  CERTIFICATE_SIZE, FALSE);

  gboolean written = TRUE;
  written &= fpi_byte_writer_put_uint16_le (&writer, CERTIFICATE_MAGIC);
  written &= fpi_byte_writer_put_uint16_le (&writer, CERTIFICATE_CURVE);

  // NOTE: everything is written in little endian -> reverse some things
  // write x public key coordinate
  reverse_array (x_bytes, x_bytes_size);
  written &= fpi_byte_writer_put_data (&writer, x_bytes, x_bytes_size);
  /* add zeros as padding */
  written &=
      fpi_byte_writer_fill (&writer, 0, CERTIFICATE_MAX_KEY_SIZE - x_bytes_size);

  // write y public key coordinate
  reverse_array (y_bytes, y_bytes_size);
  written &= fpi_byte_writer_put_data (&writer, y_bytes, y_bytes_size);
  /* add zeros as padding */
  written &=
      fpi_byte_writer_fill (&writer, 0, CERTIFICATE_MAX_KEY_SIZE - y_bytes_size);

  /* add padding */
  written &= fpi_byte_writer_put_uint8 (&writer, 0);
  /* put certificate type. The host sends its own type (0); the sensor's
   * pairing *echo* of the host cert is type 2 (set by the sensor, not the
   * host). Forcing 2 here makes the sensor reject the pair (0x403). */
  written &= fpi_byte_writer_put_uint8 (&writer, 0);

  g_assert (fpi_byte_writer_get_pos (&writer) == CERTIFICATE_DATA_SIZE);
  RETURN_FALSE_AND_SET_ERROR_IF_NOT_WRITTEN (written);

  g_autoptr (EVP_PKEY) hs_privkey = NULL;
  if (!generate_hs_priv_key (&hs_privkey, error))
    {
      return FALSE;
    }

  g_autoptr (EVP_MD_CTX) ctx = EVP_MD_CTX_new ();
  gsize signature_size = 0;

  if (ctx == NULL ||
      !EVP_DigestSignInit (ctx, NULL, EVP_sha256 (), NULL, hs_privkey) ||
      !EVP_DigestSignUpdate (ctx, *host_certificate_bytes,
                             CERTIFICATE_DATA_SIZE) ||
      !EVP_DigestSignFinal (ctx, NULL, &signature_size))
    {
      g_propagate_error (error,
                         fpi_device_error_new_msg (
                             FP_DEVICE_ERROR_GENERAL,
                             "OpenSSL error occured while getting signature "
                             "length of certificate data: %s",
                             ERR_error_string (ERR_get_error (), NULL)));
      return FALSE;
    }

  g_assert (signature_size <= CERTIFICATE_MAX_SIGN_SIZE);

  g_autofree guint8 *signature = g_malloc (signature_size);

  if (!EVP_DigestSignFinal (ctx, signature, &signature_size))
    {
      g_propagate_error (error, fpi_device_error_new_msg (
                                    FP_DEVICE_ERROR_GENERAL,
                                    "OpenSSL error occured while siging "
                                    "handshake sent messages hash: %s",
                                    ERR_error_string (ERR_get_error (), NULL)));
      return FALSE;
    }

  written &= fpi_byte_writer_put_uint16_le (&writer, signature_size);

  written &= fpi_byte_writer_put_data (&writer, signature, signature_size);
  /* add zeros as padding */
  written &= fpi_byte_writer_fill (&writer, 0, CERTIFICATE_MAX_SIGN_SIZE - signature_size);
  RETURN_FALSE_AND_SET_ERROR_IF_NOT_WRITTEN (written);
  g_assert (fpi_byte_writer_get_pos (&writer) == CERTIFICATE_SIZE);

#ifdef DEBUG_SSL
  g_autofree char *host_certificate_str =
      bin2hex (*host_certificate_bytes, CERTIFICATE_SIZE);
  fp_dbg ("Genereted host certificate: %s", host_certificate_str);
#endif

  return TRUE;
}

void
free_pairing_data (SensorPairingData *pairing_data)
{
  g_clear_pointer (&pairing_data->server_cert.sign, g_free);
  g_clear_pointer (&pairing_data->server_cert.x, g_free);
  g_clear_pointer (&pairing_data->server_cert.y, g_free);
  g_clear_pointer (&pairing_data->client_cert.sign, g_free);
  g_clear_pointer (&pairing_data->client_cert.x, g_free);
  g_clear_pointer (&pairing_data->client_cert.y, g_free);
  g_clear_pointer (&pairing_data->client_cert.pub_key, EVP_PKEY_free);
  g_clear_pointer (&pairing_data->server_cert.pub_key, EVP_PKEY_free);
  g_clear_pointer (&pairing_data->client_key, EVP_PKEY_free);
}
