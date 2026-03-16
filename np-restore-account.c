/*
 * NP Restore Account (by earthonion)
 * Reads config.dat from disk and restores all fields to the registry verbatim.
 * No patching or modification - purely copies existing config.dat data.
 * Requires offline activation via offact (https://github.com/ps5-payload-dev/offact)
 * or already activated console
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#define ORBIS_USER_SERVICE_MAX_LOGIN_USERS 4
#define CONFIG_DAT_SIZE 0x1200

typedef struct { uint32_t priority; } OrbisUserServiceInitializeParams;
typedef struct {
    int32_t userId[ORBIS_USER_SERVICE_MAX_LOGIN_USERS];
} OrbisUserServiceLoginUserIdList;

int32_t sceUserServiceInitialize(OrbisUserServiceInitializeParams *params);
int32_t sceUserServiceTerminate(void);
int32_t sceUserServiceGetForegroundUser(int32_t *userId);
int32_t sceUserServiceGetUserName(int32_t userId, char *name, size_t maxSize);

/* Notifications */
typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

static void notify(const char *fmt, ...) {
    notify_request_t req;
    memset(&req, 0, sizeof(req));
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, ap);
    va_end(ap);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

/* Registry manager */
int32_t sceRegMgrSetInt(uint32_t key, int32_t value);
int32_t sceRegMgrSetStr(uint32_t key, const char *value, size_t size);
int32_t sceRegMgrSetBin(uint32_t key, const void *value, size_t size);
int32_t sceRegMgrGetInt(uint32_t key, int32_t *value);
int32_t sceRegMgrGetStr(uint32_t key, char *value, size_t size);
int32_t sceRegMgrGetBin(uint32_t key, void *value, size_t size);

/* Registry keys*/
#define REG_KEY_USERNAME      125829632   /* offset 0x04, str 17 */
#define REG_KEY_ACCOUNT_ID    125830400   /* offset 0x100, bin 8 */
#define REG_KEY_EMAIL         125830656   /* offset 0x108, str 65 */
#define REG_KEY_NP_ENV        125874183   /* offset 0x177, str 17 */
#define REG_KEY_ONLINE_ID     125874188   /* offset 0x1AD, str 17 */
#define REG_KEY_COUNTRY       125874190   /* offset 0x1BE, str 3 */
#define REG_KEY_LANGUAGE      125874191   /* offset 0x1C1, str 6 */
#define REG_KEY_LOCALE        125874192   /* offset 0x1C7, str 36 */
#define REG_KEY_FLAG_1        125830144   /* offset 0x48, int */
#define REG_KEY_FLAG_2        125831168   /* offset 0x50, int */
#define REG_KEY_FLAG_3        125831424   /* offset 0x4C, int */
#define REG_KEY_FLAG_5C       125832960   /* offset 0x5C, int */
#define REG_KEY_FIELD_1F4     125874194   /* offset 0x1F4, int */
#define REG_KEY_SIGNIN_FLAG   125874185   /* offset 0x1F8, int - CRITICAL */
#define REG_KEY_FIELD_1FC     125874186   /* offset 0x1FC, int */
#define REG_KEY_NP_0xA4       125830912   /* offset 0xA4, int */
#define REG_KEY_NP_0xB4       125831936   /* offset 0xB4, int */
#define REG_KEY_NP_0xD0       125832704   /* offset 0xD0, int */
#define REG_KEY_NP_0xD4       125882625   /* offset 0xD4, int */
#define REG_KEY_NP_0xDC       125854723   /* offset 0xDC, int */
#define REG_KEY_NP_0xF4       125833216   /* offset 0xF4, int */
#define REG_KEY_EXT_0x1100    125874189   /* offset 0x1100, str 65 */
#define REG_KEY_EXT_0x1141    125874193   /* offset 0x1141, str 11 */
#define REG_KEY_EXT_0x114C    125874195   /* offset 0x114C, str 65 */

static unsigned char cfg[CONFIG_DAT_SIZE];

static int read_file(const char *path, unsigned char *buf, size_t max_len) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, max_len);
    close(fd);
    return (n > 0) ? (int)n : -1;
}

static void restore_registry(uint32_t off) {
    int32_t val;

    /* Strings - copy verbatim from config.dat */
    sceRegMgrSetStr(REG_KEY_USERNAME + off, (const char*)&cfg[0x04], 17);
    sceRegMgrSetBin(REG_KEY_ACCOUNT_ID + off, &cfg[0x100], 8);

    if (cfg[0x108] != 0)
        sceRegMgrSetStr(REG_KEY_EMAIL + off, (const char*)&cfg[0x108], 65);
    sceRegMgrSetStr(REG_KEY_ONLINE_ID + off, (const char*)&cfg[0x1AD], 17);
    sceRegMgrSetStr(REG_KEY_NP_ENV + off, (const char*)&cfg[0x177], 17);
    sceRegMgrSetStr(REG_KEY_COUNTRY + off, (const char*)&cfg[0x1BE], 3);
    sceRegMgrSetStr(REG_KEY_LANGUAGE + off, (const char*)&cfg[0x1C1], 6);
    sceRegMgrSetStr(REG_KEY_LOCALE + off, (const char*)&cfg[0x1C7], 36);

    /* Integer flags - copy verbatim */
    memcpy(&val, &cfg[0x48], 4); sceRegMgrSetInt(REG_KEY_FLAG_1 + off, val);
    memcpy(&val, &cfg[0x4C], 4); sceRegMgrSetInt(REG_KEY_FLAG_3 + off, val);
    memcpy(&val, &cfg[0x50], 4); sceRegMgrSetInt(REG_KEY_FLAG_2 + off, val);
    memcpy(&val, &cfg[0x5C], 4); sceRegMgrSetInt(REG_KEY_FLAG_5C + off, val);
    memcpy(&val, &cfg[0x1F4], 4); sceRegMgrSetInt(REG_KEY_FIELD_1F4 + off, val);
    memcpy(&val, &cfg[0x1F8], 4); sceRegMgrSetInt(REG_KEY_SIGNIN_FLAG + off, val);
    memcpy(&val, &cfg[0x1FC], 4); sceRegMgrSetInt(REG_KEY_FIELD_1FC + off, val);
    memcpy(&val, &cfg[0xA4], 4); sceRegMgrSetInt(REG_KEY_NP_0xA4 + off, val);
    memcpy(&val, &cfg[0xB4], 4); sceRegMgrSetInt(REG_KEY_NP_0xB4 + off, val);
    memcpy(&val, &cfg[0xD0], 4); sceRegMgrSetInt(REG_KEY_NP_0xD0 + off, val);
    memcpy(&val, &cfg[0xD4], 4); sceRegMgrSetInt(REG_KEY_NP_0xD4 + off, val);
    memcpy(&val, &cfg[0xDC], 4); sceRegMgrSetInt(REG_KEY_NP_0xDC + off, val);
    memcpy(&val, &cfg[0xF4], 4); sceRegMgrSetInt(REG_KEY_NP_0xF4 + off, val);

    /* Extended strings */
    if (cfg[0x1100] != 0)
        sceRegMgrSetStr(REG_KEY_EXT_0x1100 + off, (const char*)&cfg[0x1100], 65);
    if (cfg[0x1141] != 0)
        sceRegMgrSetStr(REG_KEY_EXT_0x1141 + off, (const char*)&cfg[0x1141], 11);
    if (cfg[0x114C] != 0)
        sceRegMgrSetStr(REG_KEY_EXT_0x114C + off, (const char*)&cfg[0x114C], 65);
}

int main() {
    printf("NP Restore Account (by earthonion)\n");
    printf("Restores config.dat to registry\n\n");

    OrbisUserServiceInitializeParams params = { .priority = 0x2BC };
    sceUserServiceInitialize(&params);

    /* Get foreground user */
    int32_t fgUser = -1;
    sceUserServiceGetForegroundUser(&fgUser);
    if (fgUser < 0) {
        printf("No foreground user found\n");
        notify("No user found");
        sceUserServiceTerminate();
        return 1;
    }

    uint32_t userId = (uint32_t)fgUser;
    char userName[17] = {0};
    sceUserServiceGetUserName(userId, userName, sizeof(userName));
    printf("User: %s (0x%x)\n\n", userName, userId);

    /* Read existing config.dat from disk */
    char path[256];
    snprintf(path, sizeof(path), "/system_data/priv/home/%x/config.dat", userId);

    printf("Reading %s...\n", path);
    int n = read_file(path, cfg, sizeof(cfg));
    if (n < 0) {
        printf("Failed to read config.dat\n");
        notify("Failed to read config.dat");
        sceUserServiceTerminate();
        return 1;
    }
    printf("  Read %d bytes\n", n);

    /* Verify it looks like a config.dat (magic at offset 0) */
    if (n < 0x200) {
        printf("config.dat too small (%d bytes)\n", n);
        notify("config.dat too small");
        sceUserServiceTerminate();
        return 1;
    }

    /* Show what we're restoring */
    {
        char name[17] = {0};
        memcpy(name, &cfg[0x04], 16);
        char online_id[17] = {0};
        memcpy(online_id, &cfg[0x1AD], 16);
        char country[3] = {0};
        memcpy(country, &cfg[0x1BE], 2);
        uint64_t acct_id = 0;
        memcpy(&acct_id, &cfg[0x100], 8);

        printf("\n  Username:  %s\n", name);
        printf("  Online ID: %s\n", online_id);
        printf("  Country:   %s\n", country);
        printf("  Account:   0x%lx\n", acct_id);
    }

    /* Find account slot in registry */
    int account_numb = 0;
    char cfg_username[17] = {0};
    memcpy(cfg_username, &cfg[0x04], 16);

    for (int n = 1; n <= 16; n++) {
        uint32_t off = (n - 1) * 65536;
        char name[32] = {0};
        sceRegMgrGetStr(REG_KEY_USERNAME + off, name, sizeof(name));
        if (name[0] && strcmp(name, cfg_username) == 0) {
            account_numb = n;
            break;
        }
    }

    /* If no existing slot found, find first empty slot */
    if (account_numb == 0) {
        for (int n = 1; n <= 16; n++) {
            uint32_t off = (n - 1) * 65536;
            char name[32] = {0};
            sceRegMgrGetStr(REG_KEY_USERNAME + off, name, sizeof(name));
            if (name[0] == 0) {
                account_numb = n;
                printf("\n  No existing slot found, using empty slot %d\n", n);
                break;
            }
        }
    }

    if (account_numb == 0) {
        printf("No registry slot available\n");
        notify("No registry slot available");
        sceUserServiceTerminate();
        return 1;
    }

    printf("\nRestoring to registry slot %d...\n", account_numb);

    uint32_t slot_off = (account_numb - 1) * 65536;

    /* Write to both base (slot 0) and per-slot offsets */
    restore_registry(0);
    if (account_numb > 1)
        restore_registry(slot_off);

    printf("  Registry restored (slot %d)\n", account_numb);

    printf("\nDone! Reboot to apply changes.\n");
    notify("Account restored from config.dat! Reboot to apply.");

    sceUserServiceTerminate();
    return 0;
}
