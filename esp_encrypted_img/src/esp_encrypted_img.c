/*
 * SPDX-FileCopyrightText: 2015-2022 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdio.h>
#include "esp_encrypted_img.h"
#include <errno.h>
#include <esp_log.h>
#include <esp_err.h>

#include "mbedtls/version.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/gcm.h"
#include "sys/param.h"

static const char *TAG = "esp_encrypted_img";

typedef enum {
    ESP_PRE_ENC_IMG_READ_MAGIC,
    ESP_PRE_ENC_IMG_READ_GCM,
    ESP_PRE_ENC_IMG_READ_IV,
    ESP_PRE_ENC_IMG_READ_BINSIZE,
    ESP_PRE_ENC_IMG_READ_AUTH,
    ESP_PRE_ENC_IMG_READ_EXTRA_HEADER,
    ESP_PRE_ENC_DATA_DECODE_STATE,
} esp_encrypted_img_state;

#define GCM_KEY_SIZE        32
#define MAGIC_SIZE          4
#define ENC_GCM_KEY_SIZE    384
#define IV_SIZE             16
#define BIN_SIZE_DATA       4
#define AUTH_SIZE           16
#define RESERVED_HEADER     88

struct esp_encrypted_img_handle {
    char *rsa_pem;
    size_t rsa_len;
    uint32_t binary_file_len;
    uint32_t binary_file_read;
    char gcm_key[GCM_KEY_SIZE];
    char iv[IV_SIZE];
    char auth_tag[AUTH_SIZE];
    esp_encrypted_img_state state;
    mbedtls_gcm_context gcm_ctx;
    size_t cache_buf_len;
    char *cache_buf;
};

typedef struct {
    char magic[MAGIC_SIZE];
    char enc_gcm[ENC_GCM_KEY_SIZE];
    char iv[IV_SIZE];
    char bin_size[BIN_SIZE_DATA];
    char auth[AUTH_SIZE];
    char extra_header[RESERVED_HEADER];
} pre_enc_bin_header;
#define HEADER_DATA_SIZE    sizeof(pre_enc_bin_header)

// Magic Byte is created using command: echo -n "esp_encrypted_img" | sha256sum
static uint32_t esp_enc_img_magic = 0x0788b6cf;

typedef struct esp_encrypted_img_handle esp_encrypted_img_t;

static int decipher_gcm_key(const char *enc_gcm, esp_encrypted_img_t *handle)
{
    int ret = 1;
    size_t olen = 0;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "mbedtls_pk_encrypt";

    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    mbedtls_pk_init( &pk );

    if ((ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func,
                                      &entropy, (const unsigned char *) pers,
                                      strlen(pers))) != 0) {
        ESP_LOGE(TAG, "failed\n  ! mbedtls_ctr_drbg_seed returned -0x%04x\n", (unsigned int) - ret);
        goto exit;
    }

#if (MBEDTLS_VERSION_NUMBER < 0x03000000)
    if ( (ret = mbedtls_pk_parse_key(&pk, (const unsigned char *) handle->rsa_pem, handle->rsa_len, NULL, 0)) != 0) {
#else
    if ( (ret = mbedtls_pk_parse_key(&pk, (const unsigned char *) handle->rsa_pem, handle->rsa_len, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
#endif
        ESP_LOGE(TAG, "failed\n  ! mbedtls_pk_parse_keyfile returned -0x%04x\n", (unsigned int) - ret );
        goto exit;
    }

    if (( ret = mbedtls_pk_decrypt( &pk, (const unsigned char *)enc_gcm, ENC_GCM_KEY_SIZE, (unsigned char *)handle->gcm_key, &olen, GCM_KEY_SIZE,
                                    mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 ) {
        ESP_LOGE(TAG, "failed\n  ! mbedtls_pk_decrypt returned -0x%04x\n", (unsigned int) - ret );
        goto exit;
    }
    handle->cache_buf = realloc(handle->cache_buf, 16);
    if (!handle->cache_buf) {
        return ESP_ERR_NO_MEM;
    }
    handle->state = ESP_PRE_ENC_IMG_READ_IV;
    handle->binary_file_read = 0;
    handle->cache_buf_len = 0;
exit:
    mbedtls_pk_free( &pk );
    mbedtls_entropy_free( &entropy );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    free(handle->rsa_pem);
    handle->rsa_pem = NULL;

    return (ret);
}

esp_decrypt_handle_t esp_encrypted_img_decrypt_start(const esp_decrypt_cfg_t *cfg)
{
    ESP_LOGI(TAG, "***********CHECKPOINT 1**************");
    if (cfg == NULL || cfg->rsa_priv_key == NULL) {
        ESP_LOGE(TAG, "esp_encrypted_img_decrypt_start : Invalid argument");
        return NULL;
    }
    ESP_LOGI(TAG, "Starting Decryption Process");

    esp_encrypted_img_t *handle = calloc(1, sizeof(esp_encrypted_img_t));
    if (!handle) {
        ESP_LOGE(TAG, "Couldn't allocate memory to handle");
        goto failure;
    }

    handle->rsa_pem = calloc(1, cfg->rsa_priv_key_len);
    if (!handle->rsa_pem) {
        ESP_LOGE(TAG, "Couldn't allocate memory to handle->rsa_pem");
        goto failure;
    }

    handle->cache_buf = calloc(1, ENC_GCM_KEY_SIZE);
    if (!handle->cache_buf) {
        ESP_LOGE(TAG, "Couldn't allocate memory to handle->cache_buf");
        goto failure;
    }

    memcpy(handle->rsa_pem, cfg->rsa_priv_key, cfg->rsa_priv_key_len);
    handle->rsa_len = cfg->rsa_priv_key_len;
    handle->state = ESP_PRE_ENC_IMG_READ_MAGIC;

    esp_decrypt_handle_t ctx = (esp_decrypt_handle_t)handle;
    return ctx;

failure:
    if (handle) {
        free(handle->rsa_pem);
        free(handle);
    }
    return NULL;
}

static esp_err_t process_bin(esp_encrypted_img_t *handle, pre_enc_decrypt_arg_t *args, int curr_index)
{
    size_t data_len = args->data_in_len;
    size_t data_out_size = args->data_out_len;
#if !(MBEDTLS_VERSION_NUMBER < 0x03000000)
    size_t olen;
#endif
    handle->binary_file_read += data_len - curr_index;
    int dec_len = 0;
    if (handle->binary_file_read != handle->binary_file_len) {
        size_t copy_len = 0;

        if ((handle->cache_buf_len + (data_len - curr_index)) - (handle->cache_buf_len + (data_len - curr_index)) % 16 > 0) {
            data_out_size = (handle->cache_buf_len + (data_len - curr_index)) - (handle->cache_buf_len + (data_len - curr_index)) % 16;
            args->data_out = realloc(args->data_out, data_out_size);
            if (!args->data_out) {
                return ESP_ERR_NO_MEM;
            }
        }
        if (handle->cache_buf_len != 0) {
            copy_len = MIN(16 - handle->cache_buf_len, data_len - curr_index);
            memcpy(handle->cache_buf + handle->cache_buf_len, args->data_in + curr_index, copy_len);
            handle->cache_buf_len += copy_len;
            if (handle->cache_buf_len != 16) {
                args->data_out_len = 0;
                return ESP_ERR_NOT_FINISHED;
            }
#if (MBEDTLS_VERSION_NUMBER < 0x03000000)
            if (mbedtls_gcm_update(&handle->gcm_ctx, 16, (const unsigned char *)handle->cache_buf, (unsigned char *) args->data_out) != 0) {
#else
            if (mbedtls_gcm_update(&handle->gcm_ctx, (const unsigned char *)handle->cache_buf, 16, (unsigned char *) args->data_out, data_out_size, &olen) != 0) {
#endif
                return ESP_FAIL;
            }
            dec_len = 16;
        }
        handle->cache_buf_len = (data_len - curr_index - copy_len) % 16;
        if (handle->cache_buf_len != 0) {
            data_len -= handle->cache_buf_len;
            memcpy(handle->cache_buf, args->data_in + (data_len), handle->cache_buf_len);
        }

        if (data_len - copy_len - curr_index > 0) {
#if (MBEDTLS_VERSION_NUMBER < 0x03000000)
            if (mbedtls_gcm_update(&handle->gcm_ctx, data_len - copy_len - curr_index, (const unsigned char *)args->data_in + curr_index + copy_len, (unsigned char *)args->data_out + dec_len) != 0) {
#else
            if (mbedtls_gcm_update(&handle->gcm_ctx, (const unsigned char *)args->data_in + curr_index + copy_len, data_len - copy_len - curr_index, (unsigned char *)args->data_out + dec_len, data_out_size - dec_len, &olen) != 0) {
#endif
                return ESP_FAIL;
            }
        }
        args->data_out_len = dec_len + data_len - curr_index - copy_len;
        return ESP_ERR_NOT_FINISHED;
    }
    data_out_size = handle->cache_buf_len + data_len - curr_index;
    args->data_out = realloc(args->data_out, data_out_size);
    if (!args->data_out) {
        return ESP_ERR_NO_MEM;
    }
    size_t copy_len = 0;

    copy_len = MIN(16 - handle->cache_buf_len, data_len - curr_index);
    memcpy(handle->cache_buf + handle->cache_buf_len, args->data_in + curr_index, copy_len);
    handle->cache_buf_len += copy_len;
#if (MBEDTLS_VERSION_NUMBER < 0x03000000)
    if (mbedtls_gcm_update(&handle->gcm_ctx, handle->cache_buf_len, (const unsigned char *)handle->cache_buf, (unsigned char *)args->data_out) != 0) {
#else
    if (mbedtls_gcm_update(&handle->gcm_ctx,  (const unsigned char *)handle->cache_buf, handle->cache_buf_len, (unsigned char *)args->data_out, data_out_size, &olen) != 0) {
#endif
        return ESP_FAIL;
    }
    if (data_len - curr_index - copy_len > 0) {
#if (MBEDTLS_VERSION_NUMBER < 0x03000000)
        if (mbedtls_gcm_update(&handle->gcm_ctx, data_len - curr_index - copy_len, (const unsigned char *)(args->data_in + curr_index + copy_len), (unsigned char *)(args->data_out + 16)) != 0) {
#else
        if (mbedtls_gcm_update(&handle->gcm_ctx,  (const unsigned char *)(args->data_in + curr_index + copy_len), data_len - curr_index - copy_len, (unsigned char *)(args->data_out + 16), data_out_size - 16, &olen) != 0) {
#endif
            return ESP_FAIL;
        }
    }

    args->data_out_len = handle->cache_buf_len + data_len - copy_len - curr_index;
    handle->cache_buf_len = 0;

    return ESP_OK;
}

static void read_and_cache_data(esp_encrypted_img_t *handle, pre_enc_decrypt_arg_t *args, int *curr_index, int data_size)
{
    const int data_left = data_size - handle->binary_file_read;
    const int data_recv = args->data_in_len - *curr_index;
    if (handle->state == ESP_PRE_ENC_IMG_READ_IV) {
        memcpy(handle->iv + handle->cache_buf_len, args->data_in + *curr_index, MIN(data_recv, data_left));
    } else if (handle->state == ESP_PRE_ENC_IMG_READ_AUTH) {
        memcpy(handle->auth_tag + handle->cache_buf_len, args->data_in + *curr_index, MIN(data_recv, data_left));
    } else {
        memcpy(handle->cache_buf + handle->cache_buf_len, args->data_in + *curr_index, MIN(data_recv, data_left));
    }
    handle->cache_buf_len += MIN(data_recv, data_left);
    int temp = *curr_index;
    *curr_index += MIN(data_recv, data_left);
    handle->binary_file_read += MIN(args->data_in_len - temp, data_left);
}

esp_err_t esp_encrypted_img_decrypt_data(esp_decrypt_handle_t ctx, pre_enc_decrypt_arg_t *args)
{
    if (ctx == NULL || args == NULL || args->data_in == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_encrypted_img_t *handle = (esp_encrypted_img_t *)ctx;
    if (handle == NULL) {
        ESP_LOGE(TAG, "esp_encrypted_img_decrypt_data: Invalid argument");
        return ESP_ERR_INVALID_ARG;
    }

    // // ESP_LOGI(TAG, "Before");
    // // ESP_LOGI(TAG, "  rsa_pem: %p", handle->rsa_pem);
    // // // ESP_LOGI(TAG, "  rsa_len: %zu", handle->rsa_len);
    // // // ESP_LOGI(TAG, "  binary_file_len: %u", (unsigned int)handle->binary_file_len);
    // ESP_LOGI(TAG, "  binary_file_read: %u", (unsigned int)handle->binary_file_read);
    // // ESP_LOGI(TAG, "  state: %d", handle->state);
    // ESP_LOGI(TAG, "  cache_buf_len: %zu", handle->cache_buf_len);
    // // ESP_LOGI(TAG, "  cache_buf: %p", handle->cache_buf);

    esp_err_t err;
    int curr_index = 0;

    switch (handle->state) {
    case ESP_PRE_ENC_IMG_READ_MAGIC:
        if (handle->cache_buf_len == 0 && (args->data_in_len - curr_index) >= MAGIC_SIZE) {
            uint32_t recv_magic = *(uint32_t *)args->data_in;

            if (recv_magic != esp_enc_img_magic) {
                ESP_LOGE(TAG, "Magic Verification failed");
                free(handle->rsa_pem);
                handle->rsa_pem = NULL;
                return ESP_FAIL;
            }
            curr_index += MAGIC_SIZE;
        } else {
            read_and_cache_data(handle, args, &curr_index, MAGIC_SIZE);
            if (handle->binary_file_read == MAGIC_SIZE) {
                uint32_t recv_magic = *(uint32_t *)handle->cache_buf;

                if (recv_magic != esp_enc_img_magic) {
                    ESP_LOGE(TAG, "Magic Verification failed");
                    free(handle->rsa_pem);
                    handle->rsa_pem = NULL;
                    return ESP_FAIL;
                }
                handle->binary_file_read = 0;
                handle->cache_buf_len = 0;
            } else {
                return ESP_ERR_NOT_FINISHED;
            }
        }
        ESP_LOGI(TAG, "Magic Verified");
        handle->state = ESP_PRE_ENC_IMG_READ_GCM;
    /* falls through */
    case ESP_PRE_ENC_IMG_READ_GCM:
        if (handle->cache_buf_len == 0 && args->data_in_len - curr_index >= ENC_GCM_KEY_SIZE) {
            if (decipher_gcm_key(args->data_in + curr_index, handle) != 0) {
                ESP_LOGE(TAG, "Unable to decipher GCM key");
                return ESP_FAIL;
            }
            curr_index += ENC_GCM_KEY_SIZE;
        } else {
            read_and_cache_data(handle, args, &curr_index, ENC_GCM_KEY_SIZE);
            if (handle->cache_buf_len == ENC_GCM_KEY_SIZE) {
                if (decipher_gcm_key(handle->cache_buf, handle) != 0) {
                    ESP_LOGE(TAG, "Unable to decipher GCM key");
                    return ESP_FAIL;
                }
            } else {
                return ESP_ERR_NOT_FINISHED;
            }
        }
    /* falls through */
    case ESP_PRE_ENC_IMG_READ_IV:
        if (handle->cache_buf_len == 0 && args->data_in_len - curr_index >= IV_SIZE) {
            memcpy(handle->iv, args->data_in + curr_index, IV_SIZE);
            handle->binary_file_read = IV_SIZE;
            curr_index += IV_SIZE;
        } else {
            read_and_cache_data(handle, args, &curr_index, IV_SIZE);
        }
        if (handle->binary_file_read == IV_SIZE) {
            handle->state = ESP_PRE_ENC_IMG_READ_BINSIZE;
            handle->binary_file_read = 0;
            handle->cache_buf_len = 0;
            mbedtls_gcm_init(&handle->gcm_ctx);
            if ((err = mbedtls_gcm_setkey(&handle->gcm_ctx, MBEDTLS_CIPHER_ID_AES, (const unsigned char *)handle->gcm_key, GCM_KEY_SIZE * 8)) != 0) {
                ESP_LOGE(TAG, "Error: mbedtls_gcm_set_key: -0x%04x\n", (unsigned int) - err);
                return ESP_FAIL;
            }
#if (MBEDTLS_VERSION_NUMBER < 0x03000000)
            if (mbedtls_gcm_starts(&handle->gcm_ctx, MBEDTLS_GCM_DECRYPT, (const unsigned char *)handle->iv, IV_SIZE, NULL, 0) != 0) {
#else
            if (mbedtls_gcm_starts(&handle->gcm_ctx, MBEDTLS_GCM_DECRYPT, (const unsigned char *)handle->iv, IV_SIZE) != 0) {
#endif
                ESP_LOGE(TAG, "Error: mbedtls_gcm_starts: -0x%04x\n", (unsigned int) - err);
                return ESP_FAIL;
            }
        } else {
            return ESP_ERR_NOT_FINISHED;
        }
    /* falls through */
    case ESP_PRE_ENC_IMG_READ_BINSIZE:
        if (handle->cache_buf_len == 0 && (args->data_in_len - curr_index) >= BIN_SIZE_DATA) {
            handle->binary_file_len = *(uint32_t *)(args->data_in + curr_index);
            curr_index += BIN_SIZE_DATA;
        } else {
            read_and_cache_data(handle, args, &curr_index, BIN_SIZE_DATA);
            if (handle->binary_file_read == BIN_SIZE_DATA) {
                handle->binary_file_len = *(uint32_t *)handle->cache_buf;
            } else {
                return ESP_ERR_NOT_FINISHED;
            }
        }
        handle->state = ESP_PRE_ENC_IMG_READ_AUTH;
        handle->binary_file_read = 0;
        handle->cache_buf_len = 0;
    /* falls through */
    case ESP_PRE_ENC_IMG_READ_AUTH:
        if (handle->cache_buf_len == 0 && args->data_in_len - curr_index >= AUTH_SIZE) {
            memcpy(handle->auth_tag, args->data_in + curr_index, AUTH_SIZE);
            handle->binary_file_read = AUTH_SIZE;
            curr_index += AUTH_SIZE;
        } else {
            read_and_cache_data(handle, args, &curr_index, AUTH_SIZE);
        }
        if (handle->binary_file_read == AUTH_SIZE) {
            handle->state = ESP_PRE_ENC_IMG_READ_EXTRA_HEADER;
            handle->binary_file_read = 0;
            handle->cache_buf_len = 0;
        } else {
            return ESP_ERR_NOT_FINISHED;
        }
    /* falls through */
    case ESP_PRE_ENC_IMG_READ_EXTRA_HEADER: {
        int temp = curr_index;
        curr_index += MIN(args->data_in_len - curr_index, RESERVED_HEADER - handle->binary_file_read);
        handle->binary_file_read += MIN(args->data_in_len - temp, RESERVED_HEADER - handle->binary_file_read);
        if (handle->binary_file_read == RESERVED_HEADER) {
            handle->state = ESP_PRE_ENC_DATA_DECODE_STATE;
            handle->binary_file_read = 0;
            handle->cache_buf_len = 0;
        } else {
            return ESP_ERR_NOT_FINISHED;
        }
    }
/* falls through */
    case ESP_PRE_ENC_DATA_DECODE_STATE:
        err = process_bin(handle, args, curr_index);
        return err;
    }
    return ESP_OK;
}

esp_err_t esp_encrypted_img_decrypt_end(esp_decrypt_handle_t ctx)
{
    if (ctx == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    esp_encrypted_img_t *handle = (esp_encrypted_img_t *)ctx;
    esp_err_t err = ESP_OK;
    if (handle == NULL) {
        ESP_LOGE(TAG, "esp_encrypted_img_decrypt_data: Invalid argument");
        return ESP_ERR_INVALID_ARG;
    }
    if (handle->state == ESP_PRE_ENC_DATA_DECODE_STATE) {
        if (handle->cache_buf_len != 0 || handle->binary_file_read != handle->binary_file_len) {
            ESP_LOGE(TAG, "Invalid operation");
            err = ESP_FAIL;
            goto exit;
        }

        unsigned char got_auth[AUTH_SIZE] = {0};
#if (MBEDTLS_VERSION_NUMBER < 0x03000000)
        err = mbedtls_gcm_finish(&handle->gcm_ctx, got_auth, AUTH_SIZE);
#else
        size_t olen;
        err = mbedtls_gcm_finish(&handle->gcm_ctx, NULL, 0, &olen, got_auth, AUTH_SIZE);
#endif
        if (err != 0) {
            ESP_LOGE(TAG, "Error: %d", err);
            err = ESP_FAIL;
            goto exit;
        }
        if (memcmp(got_auth, handle->auth_tag, AUTH_SIZE) != 0) {
            ESP_LOGE(TAG, "Invalid Auth");
            err = ESP_FAIL;
            goto exit;
        }
    }
    err = ESP_OK;
exit:
    mbedtls_gcm_free(&handle->gcm_ctx);
    if(handle->cache_buf_len != 0) {
        free(handle->cache_buf);
    }
    free(handle->rsa_pem);
    free(handle);
    return err;
}

bool esp_encrypted_img_is_complete_data_received(esp_decrypt_handle_t ctx)
{
    esp_encrypted_img_t *handle = (esp_encrypted_img_t *)ctx;
    return (handle != NULL && handle->binary_file_len == handle->binary_file_read);
}

esp_err_t esp_encrypted_img_decrypt_abort(esp_decrypt_handle_t ctx)
{
    esp_encrypted_img_t *handle = (esp_encrypted_img_t *)ctx;
    if (handle == NULL) {
        ESP_LOGE(TAG, "esp_encrypted_img_decrypt_data: Invalid argument");
        return ESP_ERR_INVALID_ARG;
    }
    mbedtls_gcm_free(&handle->gcm_ctx);
    free(handle->cache_buf);
    free(handle->rsa_pem);
    free(handle);
    return ESP_OK;
}

uint16_t esp_encrypted_img_get_header_size(void)
{
    return HEADER_DATA_SIZE;
}

void print_decrypt_handle(esp_decrypt_handle_t decrypt_handle) {
    esp_encrypted_img_t *handle = (esp_encrypted_img_t *)decrypt_handle;
    if (handle == NULL) {
        ESP_LOGE(TAG, "Invalid decrypt handle");
        return;
    }

    ESP_LOGI(TAG, "Decrypt Handle Contents:");
    ESP_LOGI(TAG, "  binary_file_len: %u", (unsigned int)handle->binary_file_len);
    ESP_LOGI(TAG, "  binary_file_read: %u", (unsigned int)handle->binary_file_read);
    ESP_LOGI(TAG, "  rsa_len: %u", (unsigned int)handle->rsa_len);
    ESP_LOGI(TAG, "  cache_buf_len: %u", (unsigned int)handle->cache_buf_len);
    ESP_LOGI(TAG, "  state: %d", handle->state);
    ESP_LOGI(TAG, "  rsa_pem: %p", handle->rsa_pem);
    ESP_LOGI(TAG, "  cache_buf: %p", handle->cache_buf);

    if (handle->rsa_len > 0 && handle->rsa_pem) {
        ESP_LOG_BUFFER_HEX(TAG, handle->rsa_pem, handle->rsa_len);
    }

    if (handle->cache_buf_len > 0 && handle->cache_buf) {
        ESP_LOG_BUFFER_HEX(TAG, handle->cache_buf, handle->cache_buf_len);
    }

    ESP_LOGI(TAG, "  GCM Key:");
    ESP_LOG_BUFFER_HEX(TAG, handle->gcm_key, GCM_KEY_SIZE);
    ESP_LOGI(TAG, "  IV:");
    ESP_LOG_BUFFER_HEX(TAG, handle->iv, IV_SIZE);
    ESP_LOGI(TAG, "  Auth Tag:");
    ESP_LOG_BUFFER_HEX(TAG, handle->auth_tag, AUTH_SIZE);

    ESP_LOGI(TAG, "  GCM Context:");
    esp_gcm_context *gcm_ctx = &handle->gcm_ctx;
    ESP_LOGI(TAG, "    H:");
    ESP_LOG_BUFFER_HEX(TAG, gcm_ctx->H, sizeof(gcm_ctx->H));
    ESP_LOGI(TAG, "    ghash:");
    ESP_LOG_BUFFER_HEX(TAG, gcm_ctx->ghash, sizeof(gcm_ctx->ghash));
    ESP_LOGI(TAG, "    J0:");
    ESP_LOG_BUFFER_HEX(TAG, gcm_ctx->J0, sizeof(gcm_ctx->J0));
    ESP_LOGI(TAG, "    HL:");
    ESP_LOG_BUFFER_HEX(TAG, gcm_ctx->HL, sizeof(gcm_ctx->HL));
    ESP_LOGI(TAG, "    HH:");
    ESP_LOG_BUFFER_HEX(TAG, gcm_ctx->HH, sizeof(gcm_ctx->HH));
    ESP_LOGI(TAG, "    ori_j0:");
    ESP_LOG_BUFFER_HEX(TAG, gcm_ctx->ori_j0, sizeof(gcm_ctx->ori_j0));
    ESP_LOGI(TAG, "    IV pointer: %p", gcm_ctx->iv);
    ESP_LOGI(TAG, "    AAD pointer: %p", gcm_ctx->aad);
    ESP_LOGI(TAG, "    IV length: %u", (unsigned int)gcm_ctx->iv_len);
    ESP_LOGI(TAG, "    AAD length: %u", (unsigned int)gcm_ctx->aad_len);
    ESP_LOGI(TAG, "    Data length: %u", (unsigned int)gcm_ctx->data_len);
    ESP_LOGI(TAG, "    Mode: %d", gcm_ctx->mode);
    ESP_LOGI(TAG, "    IV:");
    if (gcm_ctx->iv && gcm_ctx->iv_len > 0) {
        ESP_LOG_BUFFER_HEX(TAG, gcm_ctx->iv, gcm_ctx->iv_len);
    }
    ESP_LOGI(TAG, "    AAD:");
    if (gcm_ctx->aad && gcm_ctx->aad_len > 0) {
        ESP_LOG_BUFFER_HEX(TAG, gcm_ctx->aad, gcm_ctx->aad_len);
    }
    ESP_LOGI(TAG, "    AES Context:");
    esp_aes_context *aes_ctx = &gcm_ctx->aes_ctx;
    ESP_LOGI(TAG, "      key_bytes: %u", (unsigned int)aes_ctx->key_bytes);
    ESP_LOGI(TAG, "      key_in_hardware: %u", (unsigned int)aes_ctx->key_in_hardware);
    ESP_LOG_BUFFER_HEX(TAG, aes_ctx->key, sizeof(aes_ctx->key));
}

void print_serialized_buffer(const uint8_t *buffer, size_t buffer_len)
{
    if (buffer == NULL || buffer_len == 0) {
        ESP_LOGE(TAG, "Invalid buffer or buffer length");
        return;
    }

    ESP_LOGI(TAG, "Serialized buffer contents:");
    ESP_LOGI(TAG, "  Total buffer length: %u", (unsigned int)buffer_len);

    const uint8_t *ptr = buffer;
    esp_encrypted_img_t *img = (esp_encrypted_img_t *)ptr;
    ESP_LOGI(TAG, "  esp_encrypted_img_t (offset: %u):", (unsigned int)(ptr - buffer));
    ESP_LOGI(TAG, "    binary_file_len: %u", (unsigned int)img->binary_file_len);
    ESP_LOGI(TAG, "    binary_file_read: %u", (unsigned int)img->binary_file_read);
    ESP_LOGI(TAG, "    rsa_len: %u", (unsigned int)img->rsa_len);
    ESP_LOGI(TAG, "    cache_buf_len: %u", (unsigned int)img->cache_buf_len);
    ESP_LOGI(TAG, "    state: %d", img->state);
    ESP_LOGI(TAG, "    rsa_pem: %p", img->rsa_pem);
    ESP_LOGI(TAG, "    cache_buf: %p", img->cache_buf);
    ptr += sizeof(esp_encrypted_img_t);

    ESP_LOG_BUFFER_HEX(TAG, img->gcm_key, GCM_KEY_SIZE);
    ESP_LOG_BUFFER_HEX(TAG, img->iv, IV_SIZE);
    ESP_LOG_BUFFER_HEX(TAG, img->auth_tag, AUTH_SIZE);

    ESP_LOGI(TAG, "  GCM Context (offset: %u):", (unsigned int)(ptr - buffer + GCM_KEY_SIZE + IV_SIZE + AUTH_SIZE));
    ESP_LOGI(TAG, "    H:");
    ESP_LOG_BUFFER_HEX(TAG, img->gcm_ctx.H, sizeof(img->gcm_ctx.H));
    ESP_LOGI(TAG, "    ghash:");
    ESP_LOG_BUFFER_HEX(TAG, img->gcm_ctx.ghash, sizeof(img->gcm_ctx.ghash));
    ESP_LOGI(TAG, "    J0:");
    ESP_LOG_BUFFER_HEX(TAG, img->gcm_ctx.J0, sizeof(img->gcm_ctx.J0));
    ESP_LOGI(TAG, "    HL:");
    ESP_LOG_BUFFER_HEX(TAG, img->gcm_ctx.HL, sizeof(img->gcm_ctx.HL));
    ESP_LOGI(TAG, "    HH:");
    ESP_LOG_BUFFER_HEX(TAG, img->gcm_ctx.HH, sizeof(img->gcm_ctx.HH));
    ESP_LOGI(TAG, "    ori_j0:");
    ESP_LOG_BUFFER_HEX(TAG, img->gcm_ctx.ori_j0, sizeof(img->gcm_ctx.ori_j0));
    ESP_LOGI(TAG, "    IV pointer: %p", img->gcm_ctx.iv);
    ESP_LOGI(TAG, "    AAD pointer: %p", img->gcm_ctx.aad);
    ESP_LOGI(TAG, "    IV length: %u", (unsigned int)img->gcm_ctx.iv_len);
    ESP_LOGI(TAG, "    AAD length: %u", (unsigned int)img->gcm_ctx.aad_len);
    ESP_LOGI(TAG, "    Data length: %u", (unsigned int)img->gcm_ctx.data_len);
    ESP_LOGI(TAG, "    Mode: %d", img->gcm_ctx.mode);

    if (img->rsa_pem != NULL && img->rsa_len > 0) {
        ESP_LOG_BUFFER_HEX(TAG, ptr, img->rsa_len);
        ptr += img->rsa_len;
    }

    if (img->cache_buf != NULL && img->cache_buf_len > 0) {
        ESP_LOG_BUFFER_HEX(TAG, ptr, img->cache_buf_len);
        ptr += img->cache_buf_len;
    }

    if (img->gcm_ctx.iv_len > 0) {
        ESP_LOG_BUFFER_HEX(TAG, ptr, img->gcm_ctx.iv_len);
        ptr += img->gcm_ctx.iv_len;
    }

    if (img->gcm_ctx.aad_len > 0) {
        ESP_LOG_BUFFER_HEX(TAG, ptr, img->gcm_ctx.aad_len);
    }

    ESP_LOGI(TAG, "    AES Context:");
    esp_aes_context *aes_ctx = &img->gcm_ctx.aes_ctx;
    ESP_LOGI(TAG, "      key_bytes: %u", (unsigned int)aes_ctx->key_bytes);
    ESP_LOGI(TAG, "      key_in_hardware: %u", (unsigned int)aes_ctx->key_in_hardware);
    ESP_LOG_BUFFER_HEX(TAG, aes_ctx->key, sizeof(aes_ctx->key));
}

esp_err_t esp_encrypted_img_decrypt_handle_to_nvs(esp_decrypt_handle_t decrypt_handle, uint8_t **buffer, size_t *buffer_len)
{
    if (decrypt_handle == NULL || buffer == NULL || buffer_len == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "*********************************");
    // Call the function to print the deserialized decrypt handle
    // print_decrypt_handle(decrypt_handle);


    esp_encrypted_img_t *handle = (esp_encrypted_img_t *)decrypt_handle;
    esp_gcm_context *gcm_ctx = &handle->gcm_ctx;

    // Calculate the total size needed for serialization
    size_t total_size = sizeof(esp_encrypted_img_t);
    total_size += handle->rsa_len;
    total_size += handle->cache_buf_len;
    total_size += gcm_ctx->iv_len;
    total_size += gcm_ctx->aad_len;

    // Allocate buffer
    *buffer = malloc(total_size);
    if (*buffer == NULL) {
        return ESP_ERR_NO_MEM;
    }

    uint8_t *ptr = *buffer;

    // Copy the main structure
    memcpy(ptr, handle, sizeof(esp_encrypted_img_t));
    ptr += sizeof(esp_encrypted_img_t);

    // Copy RSA PEM if it exists
    if (handle->rsa_pem != NULL && handle->rsa_len > 0) {
        memcpy(ptr, handle->rsa_pem, handle->rsa_len);
        ptr += handle->rsa_len;
    } else {
        // If RSA PEM is not copied, set the pointer in the structure to NULL
        ((esp_encrypted_img_t *)(*buffer))->rsa_pem = NULL;
    }

    // Copy cache buffer if it exists
    if (handle->cache_buf != NULL && handle->cache_buf_len > 0) {
        memcpy(ptr, handle->cache_buf, handle->cache_buf_len);
        ptr += handle->cache_buf_len;
    } else {
        // If cache buffer is not copied, set the pointer in the structure to NULL
        ((esp_encrypted_img_t *)(*buffer))->cache_buf = malloc(16);
    }

    // Serialize IV if it exists
    if (gcm_ctx->iv != NULL && gcm_ctx->iv_len > 0) {
        memcpy(ptr, gcm_ctx->iv, gcm_ctx->iv_len);
        ptr += gcm_ctx->iv_len;
    } else {
        // If IV is not copied, set the pointer in the structure to NULL
        ((esp_encrypted_img_t *)(*buffer))->gcm_ctx.iv = NULL;
    }

    // Serialize AAD if it exists
    if (gcm_ctx->aad != NULL && gcm_ctx->aad_len > 0) {
        memcpy(ptr, gcm_ctx->aad, gcm_ctx->aad_len);
        ptr += gcm_ctx->aad_len;
    } else {
        // If AAD is not copied, set the pointer in the structure to NULL
        ((esp_encrypted_img_t *)(*buffer))->gcm_ctx.aad = NULL;
    }

    *buffer_len = total_size;

    // Call the function to print the serialized buffer
    // print_serialized_buffer(*buffer, *buffer_len);

    return ESP_OK;
}


esp_err_t esp_encrypted_img_decrypt_handle_from_nvs(const uint8_t *buffer, size_t buffer_len, esp_decrypt_handle_t *decrypt_handle)
{
    if (buffer == NULL || buffer_len == 0 || decrypt_handle == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    // Print the serialized buffer before deserialization
    // print_serialized_buffer(buffer, buffer_len);

    if (buffer_len < sizeof(esp_encrypted_img_t)) {
        return ESP_ERR_INVALID_SIZE;
    }

    esp_encrypted_img_t *handle = calloc(1, sizeof(esp_encrypted_img_t));
    if (handle == NULL) {
        return ESP_ERR_NO_MEM;
    }

    const uint8_t *ptr = buffer;

    // Deserialize esp_gcm_context
    esp_gcm_context *gcm_ctx = &handle->gcm_ctx;
    
    // Reinitialize GCM context if necessary
    if (handle->state == ESP_PRE_ENC_DATA_DECODE_STATE) {
        mbedtls_gcm_init(&handle->gcm_ctx);
        if (mbedtls_gcm_setkey(&handle->gcm_ctx, MBEDTLS_CIPHER_ID_AES, (const unsigned char *)handle->gcm_key, GCM_KEY_SIZE * 8) != 0) {
            free(handle->rsa_pem);
            free(handle->cache_buf);
            free(handle);
            return ESP_FAIL;
        }
#if (MBEDTLS_VERSION_NUMBER < 0x03000000)
        if (mbedtls_gcm_starts(&handle->gcm_ctx, MBEDTLS_GCM_DECRYPT, (const unsigned char *)handle->iv, IV_SIZE, NULL, 0) != 0) {
#else
        if (mbedtls_gcm_starts(&handle->gcm_ctx, MBEDTLS_GCM_DECRYPT, (const unsigned char *)handle->iv, IV_SIZE) != 0) {
#endif
            mbedtls_gcm_free(&handle->gcm_ctx);
            free(handle->rsa_pem);
            free(handle->cache_buf);
            free(handle);
            return ESP_FAIL;
        }
    }

    // Copy the main structure
    memcpy(handle, ptr, sizeof(esp_encrypted_img_t));
    ptr += sizeof(esp_encrypted_img_t);

    // Restore RSA PEM if it exists
    if (handle->rsa_pem != NULL && handle->rsa_len > 0) {
        if (ptr + handle->rsa_len > buffer + buffer_len) {
            free(handle);
            return ESP_ERR_INVALID_SIZE;
        }
        handle->rsa_pem = malloc(handle->rsa_len);
        if (handle->rsa_pem == NULL) {
            free(handle);
            return ESP_ERR_NO_MEM;
        }
        memcpy(handle->rsa_pem, ptr, handle->rsa_len);
        ptr += handle->rsa_len;
    }

    // Restore cache buffer if it exists
    if (handle->cache_buf != NULL && handle->cache_buf_len > 0) {
        if (ptr + handle->cache_buf_len > buffer + buffer_len) {
            free(handle->rsa_pem);
            free(handle);
            return ESP_ERR_INVALID_SIZE;
        }
        handle->cache_buf = malloc(handle->cache_buf_len);
        if (handle->cache_buf == NULL) {
            free(handle->rsa_pem);
            free(handle);
            return ESP_ERR_NO_MEM;
        }
        memcpy(handle->cache_buf, ptr, handle->cache_buf_len);
        ptr += handle->cache_buf_len;
    }
    
    // Deserialize IV if it exists
    if (gcm_ctx->iv != NULL && gcm_ctx->iv_len > 0) {
        if (ptr + gcm_ctx->iv_len > buffer + buffer_len) {
            free(handle->rsa_pem);
            free(handle->cache_buf);
            free(handle);
            return ESP_ERR_INVALID_SIZE;
        }
        gcm_ctx->iv = malloc(gcm_ctx->iv_len);
        if (gcm_ctx->iv == NULL) {
            free(handle->rsa_pem);
            free(handle->cache_buf);
            free(handle);
            return ESP_ERR_NO_MEM;
        }
        memcpy((void *)gcm_ctx->iv, ptr, gcm_ctx->iv_len);
        ptr += gcm_ctx->iv_len;
    }

    // Deserialize AAD if it exists
    if (gcm_ctx->aad != NULL && gcm_ctx->aad_len > 0) {
        if (ptr + gcm_ctx->aad_len > buffer + buffer_len) {
            free(handle->rsa_pem);
            free(handle->cache_buf);
            free((void *)gcm_ctx->iv);
            free(handle);
            return ESP_ERR_INVALID_SIZE;
        }
        gcm_ctx->aad = malloc(gcm_ctx->aad_len);
        if (gcm_ctx->aad == NULL) {
            free(handle->rsa_pem);
            free(handle->cache_buf);
            free((void *)gcm_ctx->iv);
            free(handle);
            return ESP_ERR_NO_MEM;
        }
        memcpy((void *)gcm_ctx->aad, ptr, gcm_ctx->aad_len);
        ptr += gcm_ctx->aad_len;
    }

    // // Set the data_len back to the main context
    handle->gcm_ctx.data_len = gcm_ctx->data_len;

    *decrypt_handle = handle;

    // Call the function to print the deserialized decrypt handle
    // print_decrypt_handle(*decrypt_handle);

    return ESP_OK;
}
