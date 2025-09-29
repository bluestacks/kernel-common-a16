/*
 *  linux/fs/bst_hooks.c
 *
 *  This file contains BlueStacks specific hook functions.
 */
#include <mount.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/namei.h>
#include <linux/vmalloc.h>
#include <linux/errno.h>
#ifdef CONFIG_PROC_FS
#include "proc/internal.h"
#endif

#include "bst_hooks.h"

#define BST_MAX_SIZE 11
#define BST_PKGINFO_ARR_SIZE 8
#define BST_MAX_SMALL_FILE_SIZE (1024 * 1024)

unsigned int bst_proc_ino[8] = {0,};

unsigned int is_aga_mode = 1;
EXPORT_SYMBOL(is_aga_mode);

// Mapping between pid and the val
// (this will tell which file has been accessed and 
// based on this value we will return if the app is running on Bluestacks or not) 
int security_pid_val[BST_MAX_SIZE][2];
int security_pointer_index;
int security_last_pid;
int security_last_index;

// These variables will store the pkg info read from cmdline
// and there corresponding uid and tgid.
bst_pkg_tgid_uid_node* cmdline_pkginfo_arr[BST_PKGINFO_ARR_SIZE];
int cmdline_saved_index = -1;

list_init bst_trie_state = NOT_INITIALIZED;

// Root node of trie containing files/folders of interest
bst_trie_node* bst_trie_root;

static bool bst_is_pmf_app(const char *calling_pkg);

/*
 * Helper function to get task_struct from a given pid
 */
struct task_struct *get_taskstruct_from_pid(int p_id)
{
    struct pid *pid_struct = find_get_pid(p_id);
    struct task_struct *task = NULL;
    if (pid_struct == NULL)
        return NULL;
    task = pid_task(pid_struct, PIDTYPE_PID);
    return task;
}

//Function to resolve pathnames, input params - path to resolve and pointer to location
//to save resolved path name, function copied from bionic/libc/upstream-freebsd/lib/libc/stdlib/realpath.c
//with __restrict two pointers cannot point to overlapping memory regions
//return value is NULL in case of error, otherwise output is saved in resolved.
static char *realpath(const char * __restrict path, char * __restrict resolved)
{
    char *p, *q, *s;
    size_t buf_len;
    size_t left_len, resolved_len;
    int errno;
    char *left = NULL;
    char *next_token = NULL;
    char *ret = resolved;

    if (path == NULL) {
        errno = EINVAL;
        printk(KERN_WARNING "%d error while resolving realpath %d", __LINE__, errno);
        return (NULL);
    }
    if (path[0] == '\0') {
        errno = ENOENT;
        printk(KERN_WARNING "%d error while resolving realpath %d", __LINE__, errno);
        return (NULL);
    }
    if (resolved == NULL) {
        errno = EINVAL;
        printk(KERN_WARNING "%d error while resolving realpath %d", __LINE__, errno);
        return (NULL);
    }

    buf_len = strlen(path) + 1;
    left = kzalloc(buf_len, GFP_KERNEL);
    next_token = kzalloc(buf_len, GFP_KERNEL);

    if (path[0] == '/') {
        resolved[0] = '/';
        resolved[1] = '\0';
        if (path[1] == '\0')
		goto out;

        resolved_len = 1;
        left_len = strlcpy(left, path + 1, buf_len);
    } else {
        errno = EINVAL;
        // returning as all path should start from /, otherwise we are not sure what app is trying
        // to open, so in that case we do not evaluate realpath.
        // printk(KERN_WARNING "%d error while resolving realpath %d", __LINE__, errno);
        ret = NULL;
        goto out;
    }
    if (left_len >= buf_len || resolved_len >= PATH_MAX) {
        errno = ENAMETOOLONG;
        printk(KERN_WARNING "%d error while resolving realpath %d", __LINE__, errno);
        ret = NULL;
        goto out;
    }

    /*
     * Iterate over path components in `left'.
     */
    while (left_len != 0) {
        /*
         * Extract the next path component and adjust `left'
         * and its length.
         */
        p = strchr(left, '/');
        s = p ? p : left + left_len;
        if (s - left >= buf_len) {
            errno = ENAMETOOLONG;
            printk(KERN_WARNING "%d error while resolving realpath %d", __LINE__, errno);
            ret = NULL;
            goto out;
        }
        memcpy(next_token, left, s - left);
        next_token[s - left] = '\0';
        left_len -= s - left;
        if (p != NULL)
            memmove(left, s + 1, left_len + 1);
        if (resolved[resolved_len - 1] != '/') {
            if (resolved_len + 1 >= PATH_MAX) {
                errno = ENAMETOOLONG;
                printk(KERN_WARNING "%d error while resolving realpath %d", __LINE__, errno);
                ret = NULL;
                goto out;
            }
            resolved[resolved_len++] = '/';
            resolved[resolved_len] = '\0';
        }
        if (next_token[0] == '\0') {
            /* Handle consequential slashes. */
            continue;
        }
        else if (strcmp(next_token, ".") == 0)
            continue;
        else if (strcmp(next_token, "..") == 0) {
            /*
             * Strip the last path component except when we have
             * single "/"
             */
            if (resolved_len > 1) {
                resolved[resolved_len - 1] = '\0';
                q = strrchr(resolved, '/') + 1;
                *q = '\0';
                resolved_len = q - resolved;
            }
            continue;
        }

        /*
         * Append the next path component
         */
        resolved_len = strlcat(resolved, next_token, PATH_MAX);
        if (resolved_len >= PATH_MAX) {
            errno = ENAMETOOLONG;
            printk(KERN_WARNING "%d error while resolving realpath %d", __LINE__, errno);
            ret = NULL;
            goto out;
        }
    }

    /*
     * Remove trailing slash except when the resolved pathname
     * is a single "/".
     */
    if (resolved_len > 1 && resolved[resolved_len - 1] == '/')
        resolved[resolved_len - 1] = '\0';

out:
	kfree(next_token);
	kfree(left);
	return ret;
}


char* get_basename(char *path)
{
    char *base = strrchr(path, '/');
    return base ? base + 1 : path;
}

// string compare function, which resolves pathnames for the source, for example /system/./etc/../etc
// will be resolved to /system/etc/ , Path resolution happens only if path contains . or ..
// return value is output of strncmp with resolved pathname and dest value.
int bst_strncmp(const char *source, char *dest, int len)
{
    char* basename = get_basename(dest);
    if ((basename[strlen(basename) -1]) == '*') {
        len = strlen(dest) - 1;
    }
    return strncmp(source, dest, len);
}

// Strcmp function to handle wildcard for matching
int bst_strcmp(char* source, char* dest) {
    int len = strlen(dest);
    if (dest[len-1] == '*') {
        return strncmp(source, dest, len-1);
    }
    return strcmp(source, dest);
}

// If the call is from readdir hook, only comparing the filename rather that
// comparing with complete path.
int bst_strncmp_path_check(char *source, char *dest, int dest_len, bool called_from_readdir_hook) {
    if (called_from_readdir_hook) {
        char* basename = get_basename(dest);
        int baselen = strlen(basename);
        if ((basename[baselen-1]) == '*') {
            if (baselen > strlen(source))
                return 1;
            baselen = baselen -1;
        } else {
            // handling case where search string is sum and one of our path is su
            if (baselen != strlen(source))
                return 1;
        }
        return strncmp(source, basename, baselen);
    } else {
        return bst_strncmp(source, dest, dest_len);
    }
}

/*
 * Helper function to Return a node of trie containing the required file/folder name
 on success, node will be returned
 on failure, NULL will be returned
 Caller is responsible for freeing node memory, if required
 */
bst_trie_node* get_node(char* file_name) {
    bst_trie_node* node = NULL;
    if (file_name == NULL || strlen(file_name) == 0)
        return NULL;
    node = kzalloc(sizeof(bst_trie_node), GFP_KERNEL);
    if (node == NULL) {
        printk(KERN_WARNING "memory allocation failure for filename %s\n", file_name);
        return NULL;
    }
    node->file_name = kzalloc(strlen(file_name) + 1, GFP_KERNEL);
    if (node->file_name == NULL) {
        printk(KERN_WARNING "memory allocation failure for filename %s\n", file_name);
        kfree(node);
        return NULL;
    }
    strncpy(node->file_name, file_name, strlen(file_name));
    node->is_end_of_path = false;
    node->next = NULL;
    node->child = NULL;
    return node;
}

/*
 * Helper function to register a path in trie structure
 on success, return 1 else 0
 */
int insert_in_trie(const char* path) {
    bst_trie_node *prev = NULL, *curr = NULL, *tmp = NULL;
    char* buf = NULL, *malloced_path = NULL;
    char* token = NULL;
    int found = 0, retval = 0;

    if (path == NULL || strlen(path) == 0)
        return 0;

    malloced_path = kzalloc(strlen(path) + 1, GFP_KERNEL);
    if (malloced_path == NULL) {
        printk(KERN_WARNING "memory allocation failed while inserting for path %s\n", path);
        return 0;
    }
    if (BST_DEBUG) printk(KERN_WARNING "Inserting path %s in trie\n", path);
    strncpy(malloced_path, path, strlen(path));
    buf = malloced_path;
    prev = bst_trie_root;
    curr = bst_trie_root->child;

    while((token = strsep(&buf, "/")) != NULL) {
        if (strlen(token) == 0) {
            continue;
        }
        if (curr == NULL) {
            tmp = get_node(token);
            if (tmp == NULL) {
                printk(KERN_WARNING "failure to get trie node for path %s\n", path);
                goto out;
            }
            curr = tmp;
            // assign new child node
            prev->child = curr;
            prev = prev->child;
            curr = curr->child;
            continue;
        }
        if (!bst_strcmp(token, curr->file_name)) {
            if (curr->is_end_of_path) {
                // Subpath already exist and will match
                retval = 1;
                goto out;
            }
            prev = curr;
            curr = curr->child;
            continue;
        }

        //Check if token exist in list (sibling)
        found = 0;
        prev = curr;
        curr = curr->next;
        while (curr != NULL) {
            if (!bst_strcmp(token, curr->file_name)) {
                if (curr->is_end_of_path) {
                    // Subpath already exist and will match
                    retval = 1;
                    goto out;
                }
                found = 1;
                prev = curr;
                curr = curr->child;
                break;
            }
            prev = curr;
            curr = curr->next;
        }

        if (!found) {
            tmp = get_node(token);
            if (tmp == NULL) {
                printk(KERN_WARNING "failure to get trie node for path %s\n", path);
                goto out;
            }
            curr = tmp;
            // assign new sibling node
            prev->next = curr;
            prev = curr;
            curr = curr->child;
        }
    }

    prev->is_end_of_path = true;
    retval = 1;

out:
    if(malloced_path) {
        kfree (malloced_path);
        malloced_path = NULL;
    }
    return retval;
}

// Returns whether or not incoming path is of interest i.e. present in bst trie or not.
bool is_trie_member(char* path) {
    char* buf = NULL, *tmp, *token = NULL;
    bool retval = true;
    bst_trie_node* cur_dirname = NULL;
    if (path == NULL || strlen(path) == 0 || bst_trie_root == NULL)
        return retval;

    // handle case for /data/dalvik-cache/*com.bluestacks*
    if (!strncmp(path, BST_DALVIK_CACHE_PATH, strlen(BST_DALVIK_CACHE_PATH)) && strstr(path, BST_PACKAGE_1)) {
        return true;
    }

    buf = kzalloc(strlen(path) + 1, GFP_KERNEL);
    if(buf == NULL) {
        printk(KERN_WARNING "Memory allocation failed for path %s\n", path);
        goto out;
    }
    strncpy(buf, path, strlen(path));

    tmp = buf;
    token = strsep(&tmp, "/");
    cur_dirname = bst_trie_root->child;

    // Calculates the folder/file name for the current level and finds node matching the name is found in trie.
    while (token != NULL && cur_dirname != NULL) {
        if (strlen(token) == 0) {
            token = strsep(&tmp, "/");
            continue;
        }
        if (!bst_strcmp(token, cur_dirname->file_name)) {
            if (cur_dirname->is_end_of_path) {
                retval = true;
                goto out;
            }
            cur_dirname = cur_dirname->child;
            token = strsep(&tmp, "/");
            continue;
        } else if (cur_dirname->next == NULL) {
            retval = false;
            goto out;
        } else {
            cur_dirname = cur_dirname->next;
        }
    }
    retval = false;
out:
    if (buf) {
        kfree(buf);
    }
    return retval;
}

void free_bst_trie(bst_trie_node *root) {
    if (root == NULL) return;
    if (root->next != NULL)
        free_bst_trie(root->next);
    if (root->child != NULL)
        free_bst_trie(root->child);
    if (root->file_name) {
        kfree(root->file_name);
        root -> file_name = NULL;
    }
    kfree(root);
    root = NULL;
}

/*
 *  Initialize list of interested paths for which bst_hooks is to be run.
 */
void bst_init_path_trie(void) {
    int i = 0, num_entries;
    const char *interested_paths[] = { BST_DATA_APPLIB_BST_PATH, BST_DATA_MISC_BST_PATH, BST_DATA_USER_DE_BST_PATH,
        BST_SYS_DEVICES_PCI_PATH, BST_LIBGL_ES_LIB_PATH, BST_LIBGL_ES_LIB_PATH64, BST_LIBGL_EMUL_LIB_PATH,
        BST_LIBGL_EMUL_LIB_PATH64, BST_SYS_MODULE_VBOX_PATH, BST_SYS_MODULE_VIRTIO_PATH, BST_SYS_CLASS_MISC_VBOX_PATH, BST_SYS_CLASS_NET_ETH0,
        BST_DATA_DATA_BST_PATH, BST_MOUNT_BOOT_ANDROID_PATH, BST_DEVICES_VIRTUAL_MISC_VBOX_PATH, BST_DEV_VBOX_PATH,
        BST_POSTUPGRADE_PATH, BST_UEVENTD_RC_FILE, BST_SU_PATH, BST_ROOTED_SU_FULLPATH, BST_BUSYBOX_PATH, BST_SVC_MGR_PATH, BST_REPORT_PATH, BST_FOLDERD_BIN_PATH,
        BST_FOLDER_CTL_PATH, BST_SYNCFS_PATH, BST_SHUTDOWN_PATH, BST_SHUTDOWN_CORE_PATH, BST_IME_PATH,
        BST_X86_RC_FILE_1, BST_X86_RC_FILE_2, BST_X86_RC_FILE_3, BST_X86_RC_FILE_4, BST_DATA_BLUESTACKS_PROP_FILE, BST_DATA_MISC_PROP_FILE,
        BST_SYS_BUS_AC97_PATH, BST_DEVICES_VIRTUAL_MISC_VBOXUSER_PATH, BST_DEVICES_VIRTUAL_MISC_VBOXGUEST_PATH,
        BST_DEVICES_VIRTUAL_MISC_BST_GPS_PATH, BST_DEVICES_VIRTUAL_MISC_BST_IME_PATH,
        BST_DEVICES_VIRTUAL_MISC_BST_PGA_PATH, BST_FOLDER_JNI_LIB_PATH_1, BST_FOLDER_JNI_LIB_PATH_1_64,
        BST_FOLDER_JNI_LIB_PATH_2, BST_FOLDER_JNI_LIB_PATH_2_64, BST_PCSPKR_PATH, BST_DEV_IME_PATH, BST_DEV_GPS_PATH,
        BST_ARM_LIB_MARKER_FILE, BST_VIRTUAL_TOUCH_IDC_PATH,
        BST_DATA_DOWNLOADS_BST_APK_PATH, BST_DATA_PRIV_DOWNLOADS_BST_APK_PATH, BST_SDCARD_DATA_BST_APK_PATH,
        BST_SDCARD_DATA_BST_APK_PATH_2, BST_SDCARD_DATA_BST_APK_PATH_3, BST_SDCARD_DATA_BST_APK_PATH_4, BST_SDCARD_DATA_BST_APK_PATH_5,
        BST_SYSTEM_APPS_BST_APK_PATH, BST_DATA_USER_BST_PATH, BST_SYSTEM_PRIV_APPS_BST_APK_PATH, BST_SHARED_FOLDER_PATH,
        BST_SHARED_FOLDER_PATH_1, BST_SHARED_FOLDER_PATH_2, BST_SHARED_FOLDER_PATH_3, BST_SHARED_FOLDER_PATH_4,
        BST_SHARED_FOLDER_PATH_5, BST_SHARED_FOLDER_PATH_6, BST_LIBGL_ESV2_EMUL_LIB_PATH, BST_LIBGL_ESV1_EMUL_LIB_PATH, BST_LIBGL_ESV1_ENC_LIB_PATH,
        BST_LIBGL_ESV2_ENC_LIB_PATH, BST_LIBGL_ESV1_EMUL_LIB_PATH64, BST_LIB_RENDCTRL_ENC_LIB_PATH,
        BST_LIB_OPENGL_SYS_COMM_LIB_PATH, BST_LIB_PGA_LOGGER_LIB_PATH, BST_LIB_HW_GRALL_GOLDFISH_PATH,
        BST_LIB_HW_AUDIO_X86_PATH, BST_LIB_HW_CAMERA_X86_PATH, BST_LIB_HW_POWER_X86_PATH,
        BST_LIBGL_ESV2_EMUL_LIB_PATH64, BST_LIBGL_ESV1_ENC_LIB_PATH64, BST_LIBGL_ESV2_ENC_LIB_PATH64,
        BST_LIB_RENDCTRL_ENC_LIB_PATH64, BST_LIB_OPENGL_SYS_COMM_LIB_PATH64, BST_LIB_PGA_LOGGER_LIB_PATH64,
        BST_LIB_HW_GRALL_GOLDFISH_PATH64, BST_PROC_BUS_PCI_PATH, BST_PROC_VMID_PATH, BST_PROC_BSTFOLDER_EXPORTS_PATH,
        BST_PROC_BSTID_PATH, BST_PROC_GLPORT_PATH, BST_PROC_HOSTSENSORPORT_PATH, CHROME_TABS_PATH, CHROME_TABS_PATH_FOR_WRITE, BST_ARM_EMUL_PATH,
        BST_CPU_POSSIBLE_PATH , BST_CPU_PRESENT_PATH, BST_CPU_ONLINE_PATH, BST_CPU_PROP_PATH_PREFIX, BST_CPU_COMMON_FREQ_PART, BST_CPUINFO_PATH,
        BST_PROC_FILESYSTEMS_PATH, BST_PROC_IOPORT_PATH, BST_PROC_IRQ_20_VBOX_GUEST_PATH, BST_SE_LINUX_PATH, BST_BUILD_PROP_PATH, BST_PROC_NET_UNIX_PATH,
        BST_SYS_MODULE_PATH, BST_DALVIK_CACHE_ARM_PATH, BST_DEFAULT_BUILD_PROP_PATH, BST_PROC_MOD_PATH, BST_SYSTEM_LIB_MODULES_PATH,
        BST_LIB_MODULES_PATH, BST_SYS_BUS_PCI_PATH, BST_SYS_CLASS_NET_WLAN0, BST_PROC_INTERRUPTS_PATH, BST_SYS_CLASS_THERMAL,
        BST_PROC_TIMERLIST_PATH, BST_SYS_POWER_SUPPLY_PATH, BST_PROC_PATH_PREFIX, BST_SYS_KERNEL_DEBUG_X86_PATH, BST_DEV_SOCKET_BSTFOLDERD_PATH, BST_PROC_IRQ_BST_CAMERA_PATH, BST_PROC_IRQ_BST_AUDIO_PATH,
        BST_PROC_IRQ_BST_INPUT_PATH, BST_PROC_IRQ_BST_PGAIPC_PATH, BST_PROC_IRQ_BST_SENSOR_PATH, BST_CONF_PROP_PATH, BST_MOUNT_VSF_PATH, BST_PROC_GLMODE_PATH,
        BST_SYS_CLASS_INPUT, BST_PROC_MEM_PCD_ENABLED_PATH, BST_PROC_MEM_PCD_PCLIMIT_PATH, BST_PROC_MEM_PCR_ENABLED_PATH, BST_PROC_MEM_PCR_PCLIMIT_PATH,
        BST_DEVICES_VIRTUAL_MISC_BSTVMSG_PATH, BST_SYS_CLASS_MISC_BSTVMSG_PATH, BST_PROC_IRQ_BSTVMSG_PATH, BST_DEV_BSTVMSG_PATH, BST_LOGCAT_REDIRECTION_PATH};

    if (BST_DEBUG) printk(KERN_WARNING "initializing list for interested paths in bst_hooks\n");

    // bst_trie_root node of the trie
    bst_trie_root = get_node("root");
    if (bst_trie_root == NULL) {
        printk(KERN_WARNING "Error while initializing trie for root node\n");
        bst_trie_state = FAILURE;
        return;
    }
    num_entries = sizeof(interested_paths) / sizeof(interested_paths[0]);
    for (i = 0; i < num_entries; i++) {
        if(!insert_in_trie(interested_paths[i])) {
            printk(KERN_WARNING "Error while initializing trie for path %s\n", interested_paths[i]);
            bst_trie_state = FAILURE;
            free_bst_trie(bst_trie_root);
            return;
        }
    }
    bst_trie_state = INITIALIZED;
    if (BST_DEBUG) printk(KERN_WARNING "trie for interested path initialized successfully\n");
    return;
}

/*
 * Helper function to find whether we need to show bst windows folder or not.
 * @returns
 * 1 if windows folder is exposed
 * 0 if windows folder is hidden.
 */
int show_bst_shared_folder(void)
{
    //BS4-7451 etc, hardcoding to hide shared folder for specific apps till BS4-6729 is resolved
    int retval = 1, i = 0;
    char * calling_pkg = get_pkgname_from_cmdline(-1);
    static const char *restrict_shared_folder[] = {"com.xd.anothereden", "net.wrightflyer.anothereden", "com.danmemo",
            "com.wt.galaxytornado", "com.eu.danmemo", "games.wfs.anothereden", "com.kr.danmemo", "com.rtsoft.growtopia",
            "com.bandainamcoent.saoars", "com.us.danmemo", "com.Level5.BS", "com.tw.danmemo", "com.bandainamcoent.saoab",
            "com.exodus.myloveactor", "com.torpedolabs.wynn.slots", "com.wemade.mir4", "com.webzen.mua.google",
            "com.thumbage.dekaronglobal.google","com.sohoolimited.sohooholdem", "com.chemacademy", "com.playmetachain.anipangcoins", "com.wemade.wfc", "com.wemade.mir2m.thedragonkin"};
    if (calling_pkg != NULL) {
        for (i = 0; i < (sizeof(restrict_shared_folder)/sizeof(restrict_shared_folder[0])); i++) {
            if (!strncmp(calling_pkg, restrict_shared_folder[i], strlen(restrict_shared_folder[i]))) {
                retval = 0;
                break;
            }
        }

        if (bst_is_pmf_app(calling_pkg)) {
            retval = 0;
        }

        kfree(calling_pkg);
        calling_pkg = NULL;
    }

    //BS4-6729 Temporarily showing bst shared folder to all
    return retval;
}

// This function will return the packagename from the array
// corresponding to the TGID-UID combination
int get_pkginfo_from_tgiduid(int tgid, int uid) {
    bst_pkg_tgid_uid_node* node;
    int i;
    for (i = 0; i < BST_PKGINFO_ARR_SIZE; i++) {
        node = cmdline_pkginfo_arr[i];
        if (node == NULL) {
            continue;
        }
        if (node->tgid == tgid && node->uid == uid) {
            if (BST_DEBUG) printk(KERN_WARNING "get_pkginfo_from_tgiduid: tgid = %d, uid = %d, package name %s is already present in the array\n", tgid, uid, node->package_name);
            return i;
        }
    }
    return -1;
}

// This function returns the index where new node is to be added
int get_pkginfo_index(void) {
    bst_pkg_tgid_uid_node* node = NULL;
    cmdline_saved_index = (cmdline_saved_index + 1) % BST_PKGINFO_ARR_SIZE;
    node = cmdline_pkginfo_arr[cmdline_saved_index];
    if (node) {
        memset(node, 0, sizeof(bst_pkg_tgid_uid_node));
    }
    if (BST_DEBUG) printk(KERN_WARNING "get_pkginfo_index: returning index %d\n", cmdline_saved_index);
    return cmdline_saved_index;
}

// This will save the values of tgid, uid, pkgname in the array 
// and will return the index of the array where this new combination is saved.
int cache_new_pkginfo(int tgid, int uid, char* pkgname) {
    int index = get_pkginfo_index();
    bst_pkg_tgid_uid_node* node = cmdline_pkginfo_arr[index];
    if (node == NULL) {
        node = kzalloc(sizeof(bst_pkg_tgid_uid_node), GFP_KERNEL);
        if (node == NULL) {
            printk(KERN_WARNING "get_pkginfo_node: memory allocation failure for tgid = %d, uid = %d, package_name= %s\n", tgid, uid, pkgname);
            return -1;
        }
    }
    strncpy(node->package_name, pkgname, BST_MAX_CMDLINE_LEN);
    node->package_name[BST_MAX_CMDLINE_LEN - 1] = '\0';
    node->tgid = tgid;
    node->uid = uid;
    cmdline_pkginfo_arr[index] = node;
    if (BST_DEBUG) printk(KERN_WARNING "get_pkginfo_node: Return new node of index %d with values tgid  = %d, uid = %d, package_name = %s\n", index, tgid, uid, pkgname);

    return index;
}

/*
 * Helper function to get cmdline(pkgname) value of given pid
 * p_id: pid of the process whose packageName needs to be find.
 *
 * To get the packageName of current process, send -1 as p_id value.
 *
 * NOTE - make sure to free cmdline from the caller of this function after the usage.
 */
char *get_pkgname_from_cmdline(int p_id)
{
    char *cmdline = NULL;
    int res = 0;
    struct task_struct *task = NULL;
    uid_t uid = -1;
    pid_t tgid = -1;
    bst_pkg_tgid_uid_node* last_saved_node = NULL;
    int index = -1;

    if (p_id > 0) {
        task = get_taskstruct_from_pid(p_id);
    } else {
        task = current;
    }

    if (task == NULL) {
        if (BST_DEBUG) printk(KERN_WARNING "for pid : %d, no corresponding task found\n",p_id);
        return NULL;
    }

    if (BST_DEBUG) printk(KERN_WARNING "pid : %d, process name: %s (%d)\n", p_id, task->comm, task->pid);

    uid = __kuid_val(task_uid(task));
    if (uid < 10000) {
        if (BST_DEBUG) printk(KERN_WARNING "for pid : %d, uid : %d, so not getting cmdline\n", p_id, uid);
        return NULL;
    }

    tgid = task_tgid_nr(task);
    // Read cmdline of current task to cmdline
    cmdline = kzalloc(BST_MAX_CMDLINE_LEN, GFP_KERNEL);
    if (!cmdline) {
        printk(KERN_WARNING "kzalloc failed for cmdline, pid : %d, task: %s (%d)\n", p_id, task->comm, task->pid);
        return NULL;
    }
    // Check if the last saved values are equal to the current value or not
    // if equal then we will return the last saved package_name.
    if (cmdline_saved_index != -1)
        last_saved_node = cmdline_pkginfo_arr[cmdline_saved_index];
    if (last_saved_node != NULL && !last_saved_node->package_name[0] && last_saved_node->uid == uid && last_saved_node->tgid == tgid) {
        if (BST_DEBUG) printk(KERN_WARNING "uid = %d, tgid = %d returning last saved value %s\n", uid, tgid, last_saved_node->package_name);
        strncpy(cmdline, last_saved_node->package_name, BST_MAX_CMDLINE_LEN);
        cmdline[BST_MAX_CMDLINE_LEN - 1] = '\0';
        return cmdline;
    } else {
        // The last saved values were not equal so now check if the combination(TGID, UID)
        // has been cached or not if cached then return those values.
        index = get_pkginfo_from_tgiduid(tgid, uid);
        if (index != -1) {
            cmdline_saved_index = index;
            last_saved_node = cmdline_pkginfo_arr[index];
            strncpy(cmdline, last_saved_node->package_name, BST_MAX_CMDLINE_LEN);
            cmdline[BST_MAX_CMDLINE_LEN-1] = '\0';
            if (BST_DEBUG) printk(KERN_WARNING "uid = %d, tgid = %d returning value from cache %s\n", last_saved_node->uid, last_saved_node->tgid, cmdline);
            return cmdline;
        }
    }

    // TGID-uid combination not cached yet, query for packageName from cmdline
    res = get_cmdline(task, cmdline, BST_MAX_CMDLINE_LEN);
    if (res == 0) {
        printk(KERN_WARNING "Error in getting cmdline value for binary %s(%d)\n", task->comm, task->pid);
        kfree(cmdline);
        return NULL;
    }
    // Making sure that cmdline is always null terminated
    cmdline[res-1] = '\0';
    if (!strncmp(cmdline, "zygote", strlen("zygote")) ||
            !strncmp(cmdline, "system_server", strlen("system_server")) ||
            !strncmp(cmdline, "<pre-initialized>", strlen("<pre-initialized>"))) {
        if (BST_DEBUG) printk(KERN_WARNING "not caching pkginfo %s for current_uid=%d, current_pid = %d, tgid = %d\n", cmdline, uid, task->pid, tgid);
        return cmdline;
    }
    // Now save the new combination in the array and also update the bst_cmdline_last_pkgname
    index = cache_new_pkginfo(tgid, uid, cmdline);
    if (index != -1) {
        cmdline_saved_index = index;
    }
    if (BST_DEBUG) printk(KERN_WARNING "current_uid=%d, current_pid = %d, tgid = %d pkgname = %s bst_cmdline_last_pkgname = %s\n", uid, task->pid, tgid, cmdline, cmdline_pkginfo_arr[index]->package_name);
    return cmdline;
}

/*
 * Redirect specific file open/stat syscalls to redirected path conditionally
 * return NO_CHANGE - if file path is not redirected
 * return REDIRECT_TO_GIVEN_FILE - if file path is redirected to modified path(to maintain compatibilty with bst_hook_file() return values.)
 */
return_v redirect_to_given_file(struct filename *tmp,char *redirected_path)
{
    int path_len = 0;
    struct task_struct *task = current;
    return_v redirecting = NO_CHANGE;

    char * calling_pkg = get_pkgname_from_cmdline(-1);
    char *new_path = NULL;

    if (calling_pkg == NULL)
        goto out;

    if (BST_DEBUG) printk (KERN_WARNING "%s:%d:%d Trying to open file %s.\n", task->comm, task->pid, task->parent->pid, tmp->name);

    if (strncmp(calling_pkg, BST_PACKAGE_1, strlen(BST_PACKAGE_1))
            && strncmp(calling_pkg, BST_PACKAGE_2, strlen(BST_PACKAGE_2))
            && strncmp(calling_pkg, BST_PACKAGE_3, strlen(BST_PACKAGE_3))
            && strncmp(calling_pkg, BST_PACKAGE_6, strlen(BST_PACKAGE_6))) {
        //reached here means some 3rd party app checked for bluestacks specific content,so redirecting them to given redirected_path file.
        new_path = (char *)tmp->name;
        path_len = strlen(new_path);
        memset(new_path, 0, path_len);
        strncpy(new_path, redirected_path, path_len);
        redirecting = REDIRECT_TO_GIVEN_FILE;

        if (BST_DEBUG) printk (KERN_WARNING "%s:%d:%d Redirecting to %s\n", task->comm, task->pid, task->parent->pid, new_path);
    }

out:
    if (calling_pkg)
        kfree(calling_pkg);

    return redirecting;
}

/*
 * An app is trying to read contents of /data/downloads or /data/priv-downloads.
 * If it is a 3rd party app, setting random file path in place of original requested path so as to generate ENOENT.
 * Google(depending on the flag allowed_to_google) and BlueStacks specific apps are allowed to open these locations.
 * return NO_CHANGE - if file path is not redirected
 * return REDIRECT_NON_EXISTENT_PATH - if file path is redirected to non existent path(to maintain compatibilty with bst_hook_file() return values.
 */
return_v redirect_to_random_file(struct filename *tmp, file_access allowed_to_google)
{
    struct task_struct *task = current;
    char * calling_pkg = get_pkgname_from_cmdline(-1);
    char *orig_path = (char *)tmp->name;
    int orig_len = 0;
    char *new_path = NULL;
    return_v redirecting = NO_CHANGE;

    if (calling_pkg == NULL)
        goto out;

    // Bug 9273: app com.ztgame.jielan tries to detect superuser binary in /system/xbin|/system/xbin/bstk.
    // We do not let access to bstk path to any app, but /system/xbin su binary if present is accessible.
    // Hiding the same for this app only as of now.
    // if path is of /system/xbin/su and package is not of com.ztgame.jielan, let it access else block.
    if (!bst_strncmp((char *)tmp->name, BST_ROOTED_SU_FULLPATH, strlen(BST_ROOTED_SU_FULLPATH))
            && strncmp(calling_pkg, SU_NOT_ALLOWED_PACKAGES_1, strlen(calling_pkg))
            && strncmp(calling_pkg, SU_NOT_ALLOWED_PACKAGES_2, strlen(SU_NOT_ALLOWED_PACKAGES_2))) {
        goto out;
    }

    if (BST_DEBUG) printk (KERN_WARNING "%s:%d:%d Trying to open file %s\n", task->comm, task->pid, task->parent->pid, tmp->name);

    if (strncmp(calling_pkg, BST_PACKAGE_1, strlen(BST_PACKAGE_1)) &&
            strncmp(calling_pkg, BST_PACKAGE_2, strlen(BST_PACKAGE_2)) &&
            strncmp(calling_pkg, BST_PACKAGE_3, strlen(BST_PACKAGE_3)) &&
            strncmp(calling_pkg, BST_PACKAGE_4, strlen(BST_PACKAGE_4)) &&
            strncmp(calling_pkg, BST_PACKAGE_6, strlen(BST_PACKAGE_6)) &&
            strncmp(calling_pkg, ALLOWED_PACKAGES_1, strlen(ALLOWED_PACKAGES_1)) &&
            strncmp(calling_pkg, ALLOWED_PACKAGES_2, strlen(ALLOWED_PACKAGES_2)) &&
            strncmp(calling_pkg, ALLOWED_PACKAGES_3, strlen(ALLOWED_PACKAGES_3))) {
        // Calling package is neither one of our packages nor one of the android system or google package or Allowed packages(like root explorer), so redirecting them to non-existent file.

        // if calling package is one of the google packages and we want to allow this file to be read by google packages
        // returning from here, not changing path.
        if(allowed_to_google == ALLOW_GOOGLE && !strncmp(calling_pkg, BST_PACKAGE_5, strlen(BST_PACKAGE_5)))
            goto out;

        new_path = (char *)tmp->name;
        orig_len = strlen(orig_path);
        memset (new_path, 0, orig_len);
        strncpy(new_path, "/f92z78dsn82a", orig_len);
        if (BST_DEBUG) printk(KERN_WARNING "Redirecting to %s for (%s:%d)", new_path, task->comm, task->pid);
        redirecting = REDIRECT_NON_EXISTENT_PATH;
    }

out:
    if (calling_pkg)
        kfree(calling_pkg);

    return redirecting;
}

/*
 * App is trying to open arm_emul path but this path didn't exist in our system,
 * so we are redirecting these requests to app specific lib path whenever possible
 * return NO_CHANGE - if file path is not redirected
 * return REDIRECT_TO_GIVEN_FILE - if file path is redirected to modified path(to maintain compatibilty with bst_hook_file() return values.)
 */
return_v change_arm_emul_path(struct filename *tmp)
{
#define EMBEDDED_NAME_MAX	      (PATH_MAX - offsetof(struct filename, iname))
    struct task_struct *task = current;
    char * orig_filename = NULL, *pkgname = NULL, *orig_path = NULL, *new_path = NULL;
    int file_suffix_len = 0, len = 0;
    return_v redirecting = NO_CHANGE;

    // firstly copy the orig file name that they are trying to open in separate buffer
    orig_path = (char *)tmp->name;
    file_suffix_len = strlen(orig_path) - strlen(BST_ARM_EMUL_PATH) + 1;
    orig_filename = kzalloc(file_suffix_len, GFP_KERNEL);
    if (!orig_filename) {
        printk(KERN_WARNING "kzalloc failed for orig_filename for length %d\n", file_suffix_len);
        goto out;
    }
    strncpy(orig_filename, orig_path + strlen(BST_ARM_EMUL_PATH), file_suffix_len);
    // Making sure that original filename is null terminated
    orig_filename[file_suffix_len-1] = '\0';

    if (BST_DEBUG) printk(KERN_WARNING "trying to open arm_emul path for file: %s (%p:%p), interested file: %s(%p)\n", orig_path, orig_path, tmp, orig_filename, orig_filename);

    // Get packagename on whose behalf this request comes
    pkgname = get_pkgname_from_cmdline(-1);
    if (!pkgname)
        goto out;

    // Find the length of new Path where we are redirecting this original request
    len = strlen("/data/data/") + strlen(pkgname) + strlen("/lib/") + file_suffix_len;

    redirecting = REDIRECT_TO_GIVEN_FILE;
    if (BST_DEBUG) printk(KERN_WARNING "packageName: %s, new path %s new path length %d, orig file name %s\n", pkgname, new_path, len, orig_filename);

    // Now, create a new Path and make sure it remains within PATH_MAX value
    new_path = (char *)tmp->name;
    if (len > PATH_MAX)
    {
        printk(KERN_WARNING "new path length (%d) is longer than valid MAX path length %d\n", len, PATH_MAX);
        goto out;
    }
    else if (len >= EMBEDDED_NAME_MAX && (tmp->name != tmp->iname))
    {
        /*
         * Uh-oh. We have a name that's approaching PATH_MAX. Allocate a
         * separate struct filename so we can dedicate the entire
         * names_cache allocation for the pathname.
         */
        if (BST_DEBUG) printk(KERN_WARNING "allocating new structure as current path length (%d) is close to valid MAX path length %d)\n", len, PATH_MAX);
        new_path = (char *)tmp;
        tmp = kzalloc(sizeof(*tmp), GFP_KERNEL);
        if (!tmp) {
            printk(KERN_WARNING "kzalloc failed for new fileinfo struct\n");
            tmp = (struct filename *)new_path;
            goto out;
        }
        tmp->name = new_path;
    }
    /*
     * Clear oldPath content and copy redirected path information over there.
     * New path looks like this: /data/data/com.test.foo/lib/libtest.so
     * TODO: Please revisit these changes if default lib path of android
     * apps changes in future.
     */
    snprintf(new_path, PATH_MAX, "/data/data/%s/lib/%s", pkgname, orig_filename);

    if (BST_DEBUG) printk(KERN_WARNING "Modifying library path for %s(%s:%d) to %s(%d)\n", pkgname, task->comm, task->pid, new_path, strlen(new_path));

out:
    if (pkgname)
        kfree(pkgname);
    if (orig_filename)
        kfree(orig_filename);

    return redirecting;
}

/*
 *  If an app is trying to read /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq
 *  or cpuinfo_min_freq or cpuinfo_cur_freq, redirecting them to read /system/etc/cpufreq
 *  return NO_CHANGE - if file path is not redirected
 *  return REDIRECT_TO_GIVEN_FILE - if file path is redirected to modified path(to maintain compatibilty with bst_hook_file() return values.)
 */
return_v change_cpu_prop_freq_path(struct filename *tmp)
{
    // Don't do these changes for this specific app, for some reason it didn't run very well
    // if we provide new values to this app.
    const char restrict_cpuscaling_pkg[] = "com.tencent.clover";
    const char *restrict_cpufreq_path[] = {"com.tencent.cardmonster", "com.tencent.game.SSGame", "com.dts.freefireth", "com.games.bl.acing.uc", "com.games.hcr2.acing.aligames", "com.wanda.longzu.aligames", "com.skylinematrix.ggplay.snkr", "com.dodjoy.yxsm.aligames", "com.dodjoy.newllfz.qwan", "com.stickgame.los2","com.games.hc.acing.guopan"};
    struct task_struct *task = current;
    char *orig_path = NULL, *queried_filename = NULL, *pkgname = NULL;
    char *new_path = NULL;
    char *temp_cpu_path = NULL;
    int is_scaling_needed = 1, cpu_index =0;
    int orig_len = 0, mod_path_len = 0;
    return_v redirecting = NO_CHANGE;
    int num_cpus = num_online_cpus();
    int i = 0;

    // making number of cpus as 2, as some games require min 2 cpus to run(like com.ncsoft.redknights)
    // and we are already faking num of cpus present/online/possible values as 2
    if(num_cpus < 2)
        num_cpus = 2;

    // saving original filename (complete path)
    orig_path = (char *)tmp->name;
    //extracting filename by comparing CPU_FREQ in two parts to match pathname for cpu0,cpu1,etc.
    queried_filename = orig_path + strlen(BST_CPU_PROP_PATH_PREFIX) + strlen(BST_CPU_COMMON_FREQ_PART);

    //get calling packageName info
    pkgname = get_pkgname_from_cmdline(-1);

    // Case 9824, 9979 Fix
    // If the full path is of /sys/devices/system/cpu/cpu%d/cpufreq (nothing appended after),
    // DO NOT re-direct for few apps as we do not have this folder in our file system.
    // This fixes crash seen in couple of tencent apps like com.tencent.game.SSGame and com.tencent.cardmonster.
    for (i =0; i < (sizeof(restrict_cpufreq_path)/sizeof(restrict_cpufreq_path[0])); i++) {
        if (pkgname && !strncmp(pkgname, restrict_cpufreq_path[i], strlen(restrict_cpufreq_path[i])) &&
                !strcmp(orig_path + strlen(BST_CPU_PROP_PATH_PREFIX), BST_CPU_COMMON_FREQ_PART))
            goto out;
    }

    //removing freq scaling capability for misc apps - com.tencent.clover
    if(pkgname && !strncmp(pkgname, restrict_cpuscaling_pkg, strlen(restrict_cpuscaling_pkg)))
        is_scaling_needed=0;

    temp_cpu_path = orig_path + strlen(BST_CPU_PROP_PATH_PREFIX) -1 ;
    cpu_index = (int)(*temp_cpu_path) - '0';

    //We are not redirecting to /system/etc/frequency if the cpu number for which the query is more than the available online cpus in the system
    if(cpu_index >= num_cpus)
        goto out;

    if (BST_DEBUG)
        printk(KERN_WARNING "%s:%d Trying to open cpu property file %s, interested filename: %s, num_online_cpus %d for package %s, is_scaling_needed = %d \n",
                task->comm, task->pid, orig_path, queried_filename, num_online_cpus(), pkgname, is_scaling_needed);

    if (is_scaling_needed
            || ((!bst_strncmp(queried_filename, BST_CPU_MAX_FREQ_PART, strlen(BST_CPU_MAX_FREQ_PART)))
                || (!bst_strncmp(queried_filename, BST_CPU_MIN_FREQ_PART, strlen(BST_CPU_MIN_FREQ_PART)))
                || (!bst_strncmp(queried_filename, BST_CPU_CUR_FREQ_PART, strlen(BST_CPU_CUR_FREQ_PART))))) {
        // As new modified path is always less than EMBEDDED_NAME_MAX length, so no need to check all the conditions.
        // We already have sufficient space to copy the new path over the existing one.
        new_path = (char *)tmp->name;
        orig_len = strlen(orig_path);
        mod_path_len = strlen(BST_CPU_FREQ_COMMON_PATH_MODIFIED);

        strncpy(new_path, BST_CPU_FREQ_COMMON_PATH_MODIFIED, mod_path_len);
        strncpy(new_path + mod_path_len, queried_filename, orig_len - mod_path_len);
        // Making sure that new path created is null terminated
        new_path[orig_len] = '\0';
        redirecting = REDIRECT_TO_GIVEN_FILE;
        if (BST_DEBUG) printk(KERN_WARNING "Modifying cpu property for %s:%d to %s\n", task->comm, task->pid, new_path);
    }

out:
    if (pkgname)
        kfree(pkgname);

    return redirecting;
}

/*
 * An app is trying to read /proc/ path. Check if they are reading the values of its own or some other process
 * If an app is trying to read Bluestacks specific content from proc like status, cmdline, comm etc, redirect
 * it to init process data.
 * return NO_CHANGE - if file path is not redirected
 * return REDIRECT_TO_GIVEN_FILE - if file path is redirected to modified path(to maintain compatibilty with bst_hook_file() return values.)
 */
return_v redirect_bst_proc_listing(struct filename *tmp)
{
    struct task_struct *task = current;
    int f_pid = 0, mul = 1;
    char *proc_suffix = NULL, *queried_file_pkgname = NULL;
    char *new_path = NULL;
    char *orig_path = (char *)tmp->name; //orig path which process is trying to open
    int orig_len = 0;
    return_v redirecting = NO_CHANGE;
    char *ptr = orig_path + strlen(BST_PROC_PATH_PREFIX);

    // Trying to get the PID from the path if queried path is in format /proc/<pid>/cmdline etc.
    // if queried path didn't contain pid info (like for path /proc/meminfo), calculated pid value would be 0.
    for (;ptr != NULL && *ptr >= '0' && *ptr <= '9'; ptr++)
        ;
    proc_suffix = ptr;
    ptr--;
    // calculating pid(eg 123 if path is /proc/123/cmdline) in f_pid
    while (ptr >= orig_path + strlen(BST_PROC_PATH_PREFIX)) {
        if (*ptr < '0' || *ptr > '9')
            break;
        f_pid += (*ptr - '0') * mul;
        mul *= 10;
        ptr--;
    }

    // Get packagename of the requested file using pid as source
    if (f_pid > 0 && task->pid != f_pid) {
        queried_file_pkgname = get_pkgname_from_cmdline(f_pid);
        if (BST_DEBUG) printk (KERN_WARNING "%s:%d Trying to open proc file %s file_pid %d file_package %s orig_file_suffix %s\n", task->comm, task->pid, orig_path, f_pid, queried_file_pkgname, proc_suffix);
    } else {
        // Either proc path didn't contain any pid information or process is trying to open one of its own
        // proc entry. For both cases, don't do any redirection.
        goto out;
    }

    if (!queried_file_pkgname || !proc_suffix)
        goto out;

    if(!(strncmp(queried_file_pkgname, BST_PACKAGE_1, strlen(BST_PACKAGE_1))
                && (strncmp(queried_file_pkgname, BST_PACKAGE_2, strlen(BST_PACKAGE_2)))
                && (strncmp(queried_file_pkgname, BST_PACKAGE_3, strlen(BST_PACKAGE_3)))
                && (strncmp(queried_file_pkgname, BST_PACKAGE_6, strlen(BST_PACKAGE_6))) )) {
        //reached here means some 3rd party app checked for bluestacks specific content,so redirecting them to init process content.
        new_path = (char *)tmp->name;
        orig_len = strlen(orig_path);
        //memset (new_path, 0, orig_len);
        snprintf(new_path, orig_len, "/proc/1%s", proc_suffix);
        new_path[orig_len] = '\0';
        redirecting = REDIRECT_TO_GIVEN_FILE;
        if (BST_DEBUG) printk(KERN_WARNING "Modifying proc path for %s:%d to %s\n", task->comm, task->pid, new_path);
    }

out:
    if (queried_file_pkgname)
        kfree(queried_file_pkgname);

    return redirecting;
}

//function to check if app has xprop entry in .config.db by reading uid values from /data/downloads/.bstxABIApps
bool is_xprop_app(void)
{
#define XPROP_FILE_PATH "/data/downloads/.bstxABIApps"
    struct file *filp = NULL;
    char *buf = NULL;
    char *temp = NULL;
    loff_t i_size = 0;
    loff_t pos = 0;
    ssize_t bytes = 0;
    bool retval = false;
    char *token, *subtoken;
    kuid_t myuid = current_uid();
    long uid = -1;
    int err;

    filp = filp_open(XPROP_FILE_PATH, O_RDONLY, 0);
    if (IS_ERR_OR_NULL(filp)) {
        if (BST_DEBUG) printk(KERN_WARNING "Error in opening bstxABIApps file, returning\n");
        filp = NULL;
        goto out;
    }

    if (!S_ISREG(file_inode(filp)->i_mode)) {
        if (BST_DEBUG) printk(KERN_WARNING "bstXABIApps file is not a regular file, returning\n");
        goto out;
    }

    //file is opened successfully, read it in a buffer
    i_size = i_size_read(file_inode(filp));
    if (i_size <= 0) {
        if (BST_DEBUG) printk(KERN_WARNING "Error in getting size of bstxABIApps file\n");
        goto out;
    }

    buf = (char *)vzalloc(i_size);
    if (!buf) {
        if (BST_DEBUG) printk(KERN_WARNING "Error in allocating buffer for bstxABIApps file\n");
        goto out;
    }

    pos = 0;
    while (pos < i_size) {
        bytes = kernel_read(filp, buf + pos, i_size - pos, &pos);
        if (bytes < 0) {
            if (BST_DEBUG) printk(KERN_WARNING "Error in reading bstxABIApps file, error = %d\n", bytes);
            goto out;
        } else if (bytes == 0) {
            if (BST_DEBUG) printk(KERN_WARNING "bstxABIApps file read completely\n");
            break;
        }
        pos += bytes;
    }

    if (pos != i_size) {
        if (BST_DEBUG) printk(KERN_WARNING "Error in reading bstxABIApps as pos != i_size\n");
        goto out;
    }

    if (BST_DEBUG) printk(KERN_WARNING "bstxABIApps file read successfully\n");

    //bstxABIApps contains uid and packagename seperated by ;
    //Read tokens line by line, and then create subtokens using ';' as delimeter
    temp = buf;
    while ((token = strsep(&temp, "\n")) != NULL && strlen(token) > 0) {
        if ((subtoken = strsep(&token, ";")) == NULL || strlen(subtoken) == 0) {
            if (BST_DEBUG) printk(KERN_WARNING "bstxABIApps file is not in proper format, continuing from next line\n");
            continue;
        }

        err = kstrtol(subtoken, 10, &uid);
        if (err) {
            if (BST_DEBUG) printk(KERN_WARNING "error in converting string %s to long: %d\n", subtoken, err);
            goto out;
        }
        if (myuid.val == uid) {
            retval = true;
            goto out;
        }
    }

out:
    if (buf != NULL)
        vfree(buf);

    if (filp != NULL)
        filp_close(filp, NULL);

    return retval;
}

static int bst_kernel_fsstat(int dfd, const char *filename, struct kstat *stat, int flags)
{
	// vfs_fstatat(AT_FDCWD, filename, stat, 0);
	struct path path;
	unsigned lookup_flags = 0;
	int error;

	flags |= AT_NO_AUTOMOUNT;

	if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH |
		      AT_STATX_SYNC_TYPE))
		return -EINVAL;

	if (!(flags & AT_SYMLINK_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;
	if (!(flags & AT_NO_AUTOMOUNT))
		lookup_flags |= LOOKUP_AUTOMOUNT;
	if (flags & AT_EMPTY_PATH)
		lookup_flags |= LOOKUP_EMPTY;

	error = kern_path(filename, lookup_flags, &path);
	if (error)
		goto out;

	error = vfs_getattr(&path, stat, STATX_BASIC_STATS, flags);
	path_put(&path);
out:
	return error;
}

static int bst_kernel_stat(const char *filename, struct kstat *stat)
{
	return bst_kernel_fsstat(AT_FDCWD, filename, stat, 0);
}

/*
 * Some apps try to read /system/build.prop for CPU_ABI/CPU_ABI2 values.
 * As a result arm apps also retrieve x86 as CPU_ABI value, resulting in
 * incorrect app behaviour if it tries to load abi specific libs.
 * Hence, re-directing read request of build.prop file based on app's installed mode (arm/x86).
 * Related cases: Bug 4665 - com.lanjingren.ivwen crash on launch. Other apps: com.appshenqui.cilikanpian
 * return NO_CHANGE - if file path is not redirected
 * return REDIRECT_TO_GIVEN_FILE - if file path is redirected to non existent path(to maintain compatibilty with bst_hook_file() return values.)
 */
return_v change_arm_build_prop_path(struct filename *tmp, char *redirected_path)
{
    struct task_struct *task = current;
    char *calling_pkg = get_pkgname_from_cmdline(-1);
    char *orig_path = (char *)tmp->name;
    char *new_path = NULL;
    const char pkg_delimeter = ':';
    char *delim_loc = NULL;
    int index = 0;
    return_v redirecting = NO_CHANGE;

    //variable to hold arm marker file path containsArmLibs.txt
    char *arm_marker_path = NULL;

    struct kstat stat;
    int orig_len = 0;

    if (calling_pkg == NULL) {
        goto out;
    }

    if (BST_DEBUG)
        printk (KERN_WARNING "%s:%d:%d Trying to open file %s calling_pkg:%s\n",
                task->comm, task->pid, task->parent->pid, tmp->name, calling_pkg);

    // Now, we try to retrieve if app is installed in arm/x86 mode
    arm_marker_path = kzalloc(256, GFP_KERNEL);
    if (!arm_marker_path) {
        printk(KERN_WARNING "kzalloc failed for arm_marker_path, returning\n");
        goto out;
    }
    sprintf(arm_marker_path, "/data/data/%s/lib/containsArmLibs.txt", calling_pkg);

    //Checking if arm marker file is present for calling_pkg or not.
    if (bst_kernel_stat(arm_marker_path, &stat)) {
        // We reached here means no marker file is present in complete
        // calling_pkg app path.
        // trying once more if calling_pkg contains ':' as some chinese app
        // like com.kylin try to read this file from process com.kylin:ipc.
        if (BST_DEBUG) printk(KERN_WARNING "no marker found for calling_pkg %s\n", calling_pkg);
        delim_loc = strchr(calling_pkg, pkg_delimeter);
        if (delim_loc != NULL) {
            // found ':' in calling pkg, extracting substring from calling_pkg
            // to get valid package name, calling pkg value changed from this
            // point in this function
            index = delim_loc - calling_pkg;
            *(calling_pkg + index) = '\0';
            sprintf(arm_marker_path, "/data/data/%s/lib/containsArmLibs.txt", calling_pkg);

            if (bst_kernel_stat(arm_marker_path, &stat)) {
                // We reached here means no marker file is present even in
                // modified calling_pkg app path.
                // So, we will return original file to the calling pkg.
                // No redirections/modification to the original request.
                if (BST_DEBUG)
                    printk(KERN_WARNING "no marker found for modified calling_pkg also %s\n", calling_pkg);
                goto out;
            }
        } else {
            // We reached here means no marker file is present in complete
            // calling_pkg app path and there is no ':' character present
            // in app. So, we will return original file to the calling pkg.
            // No redirections/modification to the original request.
            goto out;
        }
    }

    //We return original file for arm apps with xprop entry in .config.db
    if (is_xprop_app()) {
        if (BST_DEBUG) printk(KERN_WARNING "entry for package %s found in bstxABIApps file", calling_pkg);
        goto out;
    }

    // We have reached here means we need to re-direct read for arm app. Redirecting to /data/.abipropfile
    new_path = (char *)tmp->name;
    orig_len = strlen(orig_path);
    memset (new_path, 0, orig_len);
    strncpy(new_path, redirected_path, orig_len);
    redirecting = REDIRECT_TO_GIVEN_FILE;
    if (BST_DEBUG)
        printk(KERN_WARNING "Redirecting to %s for %s(%s:%d)",
               new_path, calling_pkg, task->comm, task->pid);

out:
    if (calling_pkg)
        kfree(calling_pkg);
    calling_pkg = NULL;
    if (arm_marker_path)
        kfree(arm_marker_path);
    arm_marker_path = NULL;
    return redirecting;
}

/** Allocate a buffer to read a small regular file. */
char* _bst_read_small_file(const char* file_path, loff_t* file_size)
{
    struct file *filp = NULL;
    char *buf = NULL;
    loff_t i_size = 0;
    loff_t pos = 0;
    ssize_t bytes = 0;

    filp = filp_open(file_path, O_RDONLY, 0);
    if (IS_ERR_OR_NULL(filp)) {
        if (BST_DEBUG) printk(KERN_WARNING "Error in opening file %s, returning\n", file_path);
        filp = NULL;
        goto out;
    }

    if (!S_ISREG(file_inode(filp)->i_mode)) {
        if (BST_DEBUG) printk(KERN_WARNING "The file %s is not a regular file, returning\n", file_path);
        goto out;
    }

    /* file is opened successfully, read it in a buffer */
    i_size = i_size_read(file_inode(filp));
    if (i_size <= 0) {
        if (BST_DEBUG) printk(KERN_WARNING "Error in getting size of file %s\n", file_path);
        goto out;
    }

    if (i_size > BST_MAX_SMALL_FILE_SIZE) {
        if (BST_DEBUG) printk(KERN_WARNING "The size of the file %s is too large. \n", file_path);
        goto out;
    }

    /* The file content is expected as a string, so allocate one more byte.*/
    buf = (char *)vzalloc(i_size + 1);
    if (!buf) {
        if (BST_DEBUG) printk(KERN_WARNING "Error in allocating buffer for file %s\n", file_path);
        goto out;
    }

    pos = 0;
    while (pos < i_size) {
        bytes = kernel_read(filp, buf + pos, i_size - pos, &pos);
        if (bytes < 0) {
            if (BST_DEBUG) printk(KERN_WARNING "Error in reading file %s\n", file_path);
            vfree(buf);
            buf = NULL;
            goto out;
        } else if (bytes == 0) {
            if (BST_DEBUG) printk(KERN_WARNING "File %s read completely\n", file_path);
            break;
        }
    }

    if (pos != i_size) {
        if (BST_DEBUG) printk(KERN_WARNING "Error in reading %s as pos != i_size\n", file_path);
        vfree(buf);
        buf = NULL;
        goto out;
    }

    *file_size = i_size;
    if (BST_DEBUG) printk(KERN_WARNING "File %s read successfully\n", file_path);

out:
    if (filp != NULL)
        filp_close(filp, NULL);

    return buf;
}

/**
 * Check that whether the app is a privileged vulkan app.
 * This function will read the file /data/data/{pkg}/.self and compare the package list.
 * This function should not and will not be called frequently. Before Vulkan drvier opens
 * file /dev/vboxuser, it will create the file /data/data/{pkg}/.self first. After vboxuser is opened
 * successfully, Vulkan driver will remove the file /data/data/{pkg}/.self.
 */
bool _bst_is_vulkan_app(void)
{
    char *calling_pkg = get_pkgname_from_cmdline(-1);
    char *file_buf    = NULL;
    loff_t file_size  = 0;
    char *temp;
    char *token;
    bool ret = false;

    const char *filename = "/.self";
    char path[260]    = "/data/data/";
    strlcat(path, calling_pkg, sizeof(path));
    strlcat(path, filename, sizeof(path));

    file_buf = _bst_read_small_file(path, &file_size);
    if (!file_buf || !calling_pkg)
        goto out;

    //Read app name line by line
    temp = file_buf;
    while ((token = strsep(&temp, "\n")) != NULL && strlen(token) > 0) {
        if (strcmp(token, calling_pkg) == 0){
            ret = true;
            break;
        }
    }

out:
    if (file_buf)
        vfree(file_buf);
    if (calling_pkg)
        kfree(calling_pkg);
    return ret;
}

/**
 * Check that whether the app is a promon emulator detect app.
 * This function will read the file /data/downloads/.tmp/.pmf and compare the package list.
 * This function should not and will not be called frequently.
 * This function will be called once every time the game starts.
 */
static bool bst_is_pmf_app(const char *calling_pkg)
{
#define PMF_INDEX_MAX 10
#define PMF_FILE_PATH "/data/downloads/.tmp/.pmf"
    static struct bst_pkg_config_pmf pmf[PMF_INDEX_MAX] = {0};
    static int pmf_index = 0;
    char *file_buf, *temp, *token;
    loff_t file_size  = 0;
    bool ret = false;
    int i;

    // Filter some packages
    if (calling_pkg && (bst_str_starts_with(calling_pkg, "<pre-initialized>")
            || bst_str_starts_with(calling_pkg, "zygote")
            || bst_str_starts_with(calling_pkg, "com.android")
            || bst_str_starts_with(calling_pkg, "com.google")
            || bst_str_starts_with(calling_pkg, "com.bluestacks")
            || bst_str_starts_with(calling_pkg, "android.process"))) {
        return false;
    }

    // Read pmf cache
    for (i = 0; i < PMF_INDEX_MAX; i++) {
        if (strcmp(calling_pkg, pmf[i].pkgname) == 0)
            return pmf[i].ispmf;
    }

    file_buf = _bst_read_small_file(PMF_FILE_PATH, &file_size);
    if (!file_buf || !calling_pkg)
        goto out;

    // Read app name line by line
    temp = file_buf;
    while ((token = strsep(&temp, ";")) != NULL && strlen(token) > 0) {
        if (strcmp(token, calling_pkg) == 0) {
            ret = true;
            break;
        }
    }

    // Save to pmf cache
    memset(pmf[pmf_index].pkgname, 0, sizeof(pmf[pmf_index].pkgname));
    memcpy(pmf[pmf_index].pkgname, calling_pkg, strlen(calling_pkg));
    pmf[pmf_index].ispmf = ret;

    if(BST_DEBUG) printk(KERN_WARNING "pmfInfo: pkg %s pmf_index %d ispmf %d\n", calling_pkg, pmf_index, pmf[pmf_index].ispmf);

    pmf_index = (pmf_index + 1) % PMF_INDEX_MAX;

out:
    if (file_buf)
        vfree(file_buf);

    return ret;
}

/*
 * Creating a non-circle-call function of vfs_fstatat().
 * Avoid the below behaviour. In Linux 5.15.z
 * vfs_fstatat()
 *   > vfs_statx()
 *     > bst_hook_file()
 *       > __bst_hook_file()
 *         > vfs_fstatat()
 */
int bst_vfs_fstatat(int dfd, const char __user *filename, struct kstat *stat,
		    int flags)
{
	struct path path;
	unsigned int lookup_flags = 0;
	int error;

	flags |= AT_NO_AUTOMOUNT;

	if (flags & ~(AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_EMPTY_PATH |
		      AT_STATX_SYNC_TYPE))
		return -EINVAL;

	if (!(flags & AT_SYMLINK_NOFOLLOW))
		lookup_flags |= LOOKUP_FOLLOW;
	if (!(flags & AT_NO_AUTOMOUNT))
		lookup_flags |= LOOKUP_AUTOMOUNT;
	if (flags & AT_EMPTY_PATH)
		lookup_flags |= LOOKUP_EMPTY;
retry:
	error = user_path_at(dfd, filename, lookup_flags, &path);
	if (error)
		goto out;

	error = vfs_getattr(&path, stat, STATX_BASIC_STATS, flags);
	stat->mnt_id = real_mount(path.mnt)->mnt_id;
	stat->result_mask |= STATX_MNT_ID;
	if (path.mnt->mnt_root == path.dentry)
		stat->attributes |= STATX_ATTR_MOUNT_ROOT;
	stat->attributes_mask |= STATX_ATTR_MOUNT_ROOT;
	path_put(&path);
	if (retry_estale(error, lookup_flags)) {
		lookup_flags |= LOOKUP_REVAL;
		goto retry;
	}
out:
	return error;
}

/*
 * Some apps try to read system files to determine whether they are running on BlueStacks or not.
 * These files exist on real phones but require root permissions. So, for such cases, we are now
 * returning -EACCES error or -EPERM error to the apps.
 * return NO_CHANGE - if app is allowed to read given file
 * return REDIRECT_PERMISSION_DENIED_PATH - if file path is restricted path for given app.
 * return REDIRECT_OPERATION_NOT_PERMITTED - if file path is restricted path for all.
 */
return_v return_perm_denied_path(struct filename *tmp, file_access allowed_to_google)
{
    struct task_struct *task = current;
    char * calling_pkg = get_pkgname_from_cmdline(-1);
    return_v redirecting = REDIRECT_PERMISSION_DENIED_PATH;

    if (calling_pkg == NULL)
        goto out;

    if (BST_DEBUG) printk (KERN_WARNING "%s:%d:%d Trying to open file %s\n", task->comm, task->pid, task->parent->pid, tmp->name);
    if((allowed_to_google == ALLOW_GOOGLE && !strncmp(calling_pkg, BST_PACKAGE_5, strlen(BST_PACKAGE_5))) ||
            !strncmp(calling_pkg, BST_PACKAGE_1, strlen(BST_PACKAGE_1)) ||
            !strncmp(calling_pkg, BST_PACKAGE_2, strlen(BST_PACKAGE_2)) ||
            !strncmp(calling_pkg, BST_PACKAGE_3, strlen(BST_PACKAGE_3)) ||
            !strncmp(calling_pkg, BST_PACKAGE_4, strlen(BST_PACKAGE_4)) ||
            !strncmp(calling_pkg, BST_PACKAGE_6, strlen(BST_PACKAGE_6))) {
        // Calling package is one of com.bluestacks/com.uncube or allowed_to_google is true and package is of com.google
        // returning NO_CHANGE for such packages.
        redirecting = NO_CHANGE;
    }

out:
    if (calling_pkg)
        kfree(calling_pkg);

    return redirecting;
}

return_v return_operation_not_perm_path(struct filename *tmp, file_access allowed_to_google)
{
    struct task_struct *task = current;
    char * calling_pkg = get_pkgname_from_cmdline(-1);
    return_v redirecting = REDIRECT_OPERATION_NOT_PERMITTED;

    if (calling_pkg == NULL)
        goto out;

    if (BST_DEBUG) printk (KERN_WARNING "%s:%d:%d Trying to open file %s\n", task->comm, task->pid, task->parent->pid, tmp->name);
    if((allowed_to_google == ALLOW_GOOGLE && !strncmp(calling_pkg, BST_PACKAGE_5, strlen(BST_PACKAGE_5))) ||
            !strncmp(calling_pkg, BST_PACKAGE_1, strlen(BST_PACKAGE_1)) ||
            !strncmp(calling_pkg, BST_PACKAGE_2, strlen(BST_PACKAGE_2)) ||
            !strncmp(calling_pkg, BST_PACKAGE_3, strlen(BST_PACKAGE_3)) ||
            !strncmp(calling_pkg, BST_PACKAGE_4, strlen(BST_PACKAGE_4)) ||
            !strncmp(calling_pkg, BST_PACKAGE_6, strlen(BST_PACKAGE_6))) {
        // Calling package is one of com.bluestacks/com.uncube or allowed_to_google is true and package is of com.google
        // returning NO_CHANGE for such packages.
        redirecting = NO_CHANGE;
    }

out:
    if (calling_pkg)
        kfree(calling_pkg);

    return redirecting;
}

// Utility function to return file_access of a file
// if file matches, returns ENOENT according to the package requesting access of the file.
file_access bst_check_ENOENT_required(char* orig_path, bool called_from_readdir_hook) {

    if (!bst_strncmp_path_check(orig_path, BST_DATA_APPLIB_BST_PATH, strlen(BST_DATA_APPLIB_BST_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DATA_MISC_BST_PATH, strlen(BST_DATA_MISC_BST_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DATA_USER_DE_BST_PATH, strlen(BST_DATA_USER_DE_BST_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SYS_DEVICES_PCI_PATH, strlen(BST_SYS_DEVICES_PCI_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIBGL_ES_LIB_PATH, strlen(BST_LIBGL_ES_LIB_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIBGL_ES_LIB_PATH64, strlen(BST_LIBGL_ES_LIB_PATH64), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIBGL_EMUL_LIB_PATH, strlen(BST_LIBGL_EMUL_LIB_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIBGL_EMUL_LIB_PATH64, strlen(BST_LIBGL_EMUL_LIB_PATH64), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SYS_MODULE_VBOX_PATH, strlen(BST_SYS_MODULE_VBOX_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SYS_CLASS_MISC_VBOX_PATH, strlen(BST_SYS_CLASS_MISC_VBOX_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SYS_CLASS_NET_ETH0, strlen(BST_SYS_CLASS_NET_ETH0), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SYS_CLASS_INPUT, strlen(BST_SYS_CLASS_INPUT), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DATA_DATA_BST_PATH, strlen(BST_DATA_DATA_BST_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_MOUNT_BOOT_ANDROID_PATH, strlen(BST_MOUNT_BOOT_ANDROID_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DEVICES_VIRTUAL_MISC_VBOX_PATH, strlen(BST_DEVICES_VIRTUAL_MISC_VBOX_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DEV_VBOX_PATH, strlen(BST_DEV_VBOX_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_POSTUPGRADE_PATH, strlen(BST_POSTUPGRADE_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SU_PATH, strlen(BST_SU_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_ROOTED_SU_FULLPATH, strlen(BST_ROOTED_SU_FULLPATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_BUSYBOX_PATH, strlen(BST_BUSYBOX_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SVC_MGR_PATH, strlen(BST_SVC_MGR_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_REPORT_PATH, strlen(BST_REPORT_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_FOLDERD_BIN_PATH, strlen(BST_FOLDERD_BIN_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_FOLDER_CTL_PATH, strlen(BST_FOLDER_CTL_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SYNCFS_PATH, strlen(BST_SYNCFS_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SHUTDOWN_PATH, strlen(BST_SHUTDOWN_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SHUTDOWN_CORE_PATH, strlen(BST_SHUTDOWN_CORE_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_IME_PATH, strlen(BST_IME_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_X86_RC_FILE_2_1, strlen(BST_X86_RC_FILE_2_1), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_X86_RC_FILE_1, strlen(BST_X86_RC_FILE_1), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path+1, BST_X86_RC_FILE_1, strlen(BST_X86_RC_FILE_1), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_X86_RC_FILE_2, strlen(BST_X86_RC_FILE_2), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path+1, BST_X86_RC_FILE_2, strlen(BST_X86_RC_FILE_2), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_X86_RC_FILE_3, strlen(BST_X86_RC_FILE_3), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path+1, BST_X86_RC_FILE_3, strlen(BST_X86_RC_FILE_3), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_X86_RC_FILE_4, strlen(BST_X86_RC_FILE_4), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path+1, BST_X86_RC_FILE_4, strlen(BST_X86_RC_FILE_4), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIB_HW_AUDIO_X86_PATH, strlen(BST_LIB_HW_AUDIO_X86_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIB_HW_CAMERA_X86_PATH, strlen(BST_LIB_HW_CAMERA_X86_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIB_HW_POWER_X86_PATH, strlen(BST_LIB_HW_POWER_X86_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SYS_MODULE_VIRTIO_PATH, strlen(BST_SYS_MODULE_VIRTIO_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DATA_BLUESTACKS_PROP_FILE, strlen(BST_DATA_BLUESTACKS_PROP_FILE), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DATA_MISC_PROP_FILE, strlen(BST_DATA_MISC_PROP_FILE), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SYS_BUS_AC97_PATH, strlen(BST_SYS_BUS_AC97_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DEVICES_VIRTUAL_MISC_VBOXUSER_PATH, strlen(BST_DEVICES_VIRTUAL_MISC_VBOXUSER_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DEVICES_VIRTUAL_MISC_VBOXGUEST_PATH, strlen(BST_DEVICES_VIRTUAL_MISC_VBOXGUEST_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DEVICES_VIRTUAL_MISC_BST_GPS_PATH, strlen(BST_DEVICES_VIRTUAL_MISC_BST_GPS_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DEVICES_VIRTUAL_MISC_BST_IME_PATH, strlen(BST_DEVICES_VIRTUAL_MISC_BST_IME_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DEVICES_VIRTUAL_MISC_BST_PGA_PATH, strlen(BST_DEVICES_VIRTUAL_MISC_BST_PGA_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_FOLDER_JNI_LIB_PATH_1, strlen(BST_FOLDER_JNI_LIB_PATH_1), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_FOLDER_JNI_LIB_PATH_1_64, strlen(BST_FOLDER_JNI_LIB_PATH_1_64), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_FOLDER_JNI_LIB_PATH_2, strlen(BST_FOLDER_JNI_LIB_PATH_2), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_FOLDER_JNI_LIB_PATH_2_64, strlen(BST_FOLDER_JNI_LIB_PATH_2_64), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_PCSPKR_PATH, strlen(BST_PCSPKR_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DEV_IME_PATH, strlen(BST_DEV_IME_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DEV_GPS_PATH, strlen(BST_DEV_GPS_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_ARM_LIB_MARKER_FILE, strlen(BST_ARM_LIB_MARKER_FILE), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_VIRTUAL_TOUCH_IDC_PATH, strlen(BST_VIRTUAL_TOUCH_IDC_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SYS_KERNEL_DEBUG_X86_PATH, strlen(BST_SYS_KERNEL_DEBUG_X86_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DEV_SOCKET_BSTFOLDERD_PATH, strlen(BST_DEV_SOCKET_BSTFOLDERD_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_PROC_IRQ_20_VBOX_GUEST_PATH, strlen(BST_PROC_IRQ_20_VBOX_GUEST_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_PROC_IRQ_BST_CAMERA_PATH, strlen(BST_PROC_IRQ_BST_CAMERA_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_PROC_IRQ_BST_AUDIO_PATH, strlen(BST_PROC_IRQ_BST_AUDIO_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_PROC_IRQ_BST_INPUT_PATH, strlen(BST_PROC_IRQ_BST_INPUT_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_PROC_IRQ_BST_PGAIPC_PATH, strlen(BST_PROC_IRQ_BST_PGAIPC_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_PROC_IRQ_BST_SENSOR_PATH, strlen(BST_PROC_IRQ_BST_SENSOR_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_CONF_PROP_PATH, strlen(BST_CONF_PROP_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_MOUNT_VSF_PATH, strlen(BST_MOUNT_VSF_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_PROC_GLMODE_PATH, strlen(BST_PROC_GLMODE_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_PROC_MEM_PCD_ENABLED_PATH, strlen(BST_PROC_MEM_PCD_ENABLED_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_PROC_MEM_PCD_PCLIMIT_PATH, strlen(BST_PROC_MEM_PCD_PCLIMIT_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_PROC_MEM_PCR_ENABLED_PATH, strlen(BST_PROC_MEM_PCR_ENABLED_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_PROC_MEM_PCR_PCLIMIT_PATH, strlen(BST_PROC_MEM_PCR_PCLIMIT_PATH), called_from_readdir_hook) ||
            (!bst_strncmp_path_check(orig_path, BST_DALVIK_CACHE_PATH, strlen(BST_DALVIK_CACHE_PATH), called_from_readdir_hook) && strstr(orig_path, BST_PACKAGE_1) != NULL) ||
            !bst_strncmp_path_check(orig_path, BST_DEVICES_VIRTUAL_MISC_BSTVMSG_PATH, strlen(BST_DEVICES_VIRTUAL_MISC_BSTVMSG_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SYS_CLASS_MISC_BSTVMSG_PATH, strlen(BST_SYS_CLASS_MISC_BSTVMSG_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_PROC_IRQ_BSTVMSG_PATH, strlen(BST_PROC_IRQ_BSTVMSG_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DEV_BSTVMSG_PATH, strlen(BST_DEV_BSTVMSG_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LOGCAT_REDIRECTION_PATH, strlen(BST_LOGCAT_REDIRECTION_PATH), called_from_readdir_hook)) {
                return DO_NOT_ALLOW_ANY;
    }
    else if (!bst_strncmp_path_check(orig_path, BST_DATA_DOWNLOADS_BST_APK_PATH, strlen(BST_DATA_DOWNLOADS_BST_APK_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DATA_PRIV_DOWNLOADS_BST_APK_PATH, strlen(BST_DATA_PRIV_DOWNLOADS_BST_APK_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SDCARD_DATA_BST_APK_PATH, strlen(BST_SDCARD_DATA_BST_APK_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SDCARD_DATA_BST_APK_PATH_2, strlen(BST_SDCARD_DATA_BST_APK_PATH_2), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SDCARD_DATA_BST_APK_PATH_3, strlen(BST_SDCARD_DATA_BST_APK_PATH_3), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SDCARD_DATA_BST_APK_PATH_4, strlen(BST_SDCARD_DATA_BST_APK_PATH_4), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SDCARD_DATA_BST_APK_PATH_5, strlen(BST_SDCARD_DATA_BST_APK_PATH_5), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SYSTEM_APPS_BST_APK_PATH, strlen(BST_SYSTEM_APPS_BST_APK_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_DATA_USER_BST_PATH, strlen(BST_DATA_USER_BST_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_SYSTEM_PRIV_APPS_BST_APK_PATH, strlen(BST_SYSTEM_PRIV_APPS_BST_APK_PATH), called_from_readdir_hook)) {

        return ALLOW_GOOGLE;
    }
    else if (!bst_strncmp_path_check(orig_path, BST_SHARED_FOLDER_PATH, strlen(BST_SHARED_FOLDER_PATH), called_from_readdir_hook)
            || !bst_strncmp_path_check(orig_path, BST_SHARED_FOLDER_PATH_1, strlen(BST_SHARED_FOLDER_PATH_1), called_from_readdir_hook)
            || !bst_strncmp_path_check(orig_path, BST_SHARED_FOLDER_PATH_2, strlen(BST_SHARED_FOLDER_PATH_2), called_from_readdir_hook)
            || !bst_strncmp_path_check(orig_path, BST_SHARED_FOLDER_PATH_3, strlen(BST_SHARED_FOLDER_PATH_3), called_from_readdir_hook)
            || !bst_strncmp_path_check(orig_path, BST_SHARED_FOLDER_PATH_4, strlen(BST_SHARED_FOLDER_PATH_4), called_from_readdir_hook)
            || !bst_strncmp_path_check(orig_path, BST_SHARED_FOLDER_PATH_5, strlen(BST_SHARED_FOLDER_PATH_5), called_from_readdir_hook)
            || !bst_strncmp_path_check(orig_path, BST_SHARED_FOLDER_PATH_6, strlen(BST_SHARED_FOLDER_PATH_6), called_from_readdir_hook)) {
        if (show_bst_shared_folder() > 0)
            return ALLOW_ALL;
        else
            return ALLOW_GOOGLE;
    }
    else if (!bst_strncmp_path_check(orig_path, BST_LIBGL_ESV2_EMUL_LIB_PATH, strlen(BST_LIBGL_ESV2_EMUL_LIB_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIBGL_ESV1_EMUL_LIB_PATH, strlen(BST_LIBGL_ESV1_EMUL_LIB_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIBGL_ESV1_ENC_LIB_PATH, strlen(BST_LIBGL_ESV1_ENC_LIB_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIBGL_ESV2_ENC_LIB_PATH, strlen(BST_LIBGL_ESV2_ENC_LIB_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIBGL_ESV1_EMUL_LIB_PATH64, strlen(BST_LIBGL_ESV1_EMUL_LIB_PATH64), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIB_RENDCTRL_ENC_LIB_PATH, strlen(BST_LIB_RENDCTRL_ENC_LIB_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIB_OPENGL_SYS_COMM_LIB_PATH, strlen(BST_LIB_OPENGL_SYS_COMM_LIB_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIB_PGA_LOGGER_LIB_PATH, strlen(BST_LIB_PGA_LOGGER_LIB_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIB_HW_GRALL_GOLDFISH_PATH, strlen(BST_LIB_HW_GRALL_GOLDFISH_PATH), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIBGL_ESV2_EMUL_LIB_PATH64, strlen(BST_LIBGL_ESV2_EMUL_LIB_PATH64), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIBGL_ESV1_ENC_LIB_PATH64, strlen(BST_LIBGL_ESV1_ENC_LIB_PATH64), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIBGL_ESV2_ENC_LIB_PATH64, strlen(BST_LIBGL_ESV2_ENC_LIB_PATH64), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIB_RENDCTRL_ENC_LIB_PATH64, strlen(BST_LIB_RENDCTRL_ENC_LIB_PATH64), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIB_OPENGL_SYS_COMM_LIB_PATH64, strlen(BST_LIB_OPENGL_SYS_COMM_LIB_PATH64), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIB_PGA_LOGGER_LIB_PATH64, strlen(BST_LIB_PGA_LOGGER_LIB_PATH64), called_from_readdir_hook) ||
            !bst_strncmp_path_check(orig_path, BST_LIB_HW_GRALL_GOLDFISH_PATH64, strlen(BST_LIB_HW_GRALL_GOLDFISH_PATH64), called_from_readdir_hook)) {
        // If Engine is running in AGA mode then don't hide these libraries as they are loaded in apps's context.
        if (is_aga_mode) {
            if (BST_DEBUG) printk(KERN_WARNING "__bst_hook_file Not hiding file=%s in AGA mode", orig_path);
            return ALLOW_IN_AGA;
        } else {
            return DO_NOT_ALLOW_ANY;
        }
    }
    else if  (!called_from_readdir_hook &&
            (!bst_strncmp_path_check(orig_path, BST_PROC_VMID_PATH, strlen(BST_PROC_VMID_PATH), called_from_readdir_hook) ||
             !bst_strncmp_path_check(orig_path, BST_PROC_BSTFOLDER_EXPORTS_PATH, strlen(BST_PROC_BSTFOLDER_EXPORTS_PATH), called_from_readdir_hook) ||
             !bst_strncmp_path_check(orig_path, BST_PROC_BSTID_PATH, strlen(BST_PROC_BSTID_PATH), called_from_readdir_hook) ||
             !bst_strncmp_path_check(orig_path, BST_PROC_GLPORT_PATH, strlen(BST_PROC_GLPORT_PATH), called_from_readdir_hook) ||
             !bst_strncmp_path_check(orig_path, BST_PROC_HOSTSENSORPORT_PATH, strlen(BST_PROC_HOSTSENSORPORT_PATH), called_from_readdir_hook))) {

        return DO_NOT_ALLOW_ANY;
    }
    return ALLOW_ALL;
}

int bst_find_index_from_pid(int pid) {
    int i;
    if (pid == security_last_pid) {
        if (BST_DEBUG) printk(KERN_ERR "pid %d equal to security_last_pid so returning security_last_index %d", pid, security_last_index);
        return security_last_index;
    }
    security_last_pid = pid;
    for (i = 0; i < BST_MAX_SIZE; i++) {
        if (security_pid_val[i][0] == pid) {
            return i;
        }
    }
    return -1;
}

int bst_get_current_pointer_index(void) {
    int val = security_pointer_index % BST_MAX_SIZE;
    security_pointer_index = val + 1;
    return val;
}

/**
 * We check the value of security_pid_val[index][1] if it is equal to 27 or not
 * If it is true than we will send a different code in open call for the file meaning that the user is running on Bluestacks
 */
int bst_open_security_hook(struct filename* tmp) {
    int bst_val;
    const char* filename;

    if (IS_ERR_OR_NULL(tmp) || tmp->name == NULL)
        return 0;
    filename = tmp->name;
    if (!strncmp("/sdcard/memu012", filename, sizeof("/sdcard/memu012"))) {
        int index = bst_find_index_from_pid(current->pid);
        security_last_pid = current->pid;
        if (BST_DEBUG) printk(KERN_ERR "index for pid=%d is %d", current->pid, index);
        if (index == -1) {
            return 0;
        }
        bst_val = security_pid_val[index][1];
        if (BST_DEBUG) printk(KERN_ERR "bst_val is %d", bst_val);
        if (bst_val == 27) {
            security_pid_val[index][1] = 0;
            return 1;
        } else {
            bst_val = 0;
        }
        security_pid_val[index][1] = bst_val;
        if (BST_DEBUG) printk(KERN_ERR "initializing bst_val for index=%d to 0 filename=%s, bst_val = %d, current->pid = %d\n",index, filename, bst_val, current->pid);
    }
    return 0;
}

/* Update the value in security_pid_val table
 * "/proc/irq/9/../9/vboxguest" update the value to in table corresponding to pid to 1
 * "/sys/class/misc/memuuser" bst_val for pid should be 1 before updating and new value is (bst_val + 2)*2 = 6
 * "/system/xbin/mount.vboxsf" BLUESTACKS_CHECK should be 6 before updating and new value is (bst_val + 3) *3 = 27
 * */
void bst_stat_security_hook(struct filename* tmp) {
    int bst_val;
    char* orig_path = (char*) tmp->name;
    int pid = current->pid;
    int index = -1;
    if (!strncmp("/proc/irq/9/../9/vboxguest", orig_path, strlen("/proc/irq/9/../9/vboxguest"))) {
        index = bst_find_index_from_pid(pid);
        if (index == -1) {
            index = bst_get_current_pointer_index();
            security_pid_val[index][0] = pid;
            security_last_pid = pid;
            security_last_index = index;
        }
        bst_val = 0;
        bst_val = (bst_val + 1) * 1;
        security_pid_val[index][1] = bst_val;
        if (BST_DEBUG) printk(KERN_WARNING "pid = %d, orig_path = %s, index = %d, bst_val = %d",pid, orig_path, index, bst_val);
    }
    else if (!strncmp("/sys/class/misc/memuuser", orig_path, strlen("/sys/class/misc/memuuser"))) {
        index = bst_find_index_from_pid(pid);
        if (index == -1) {
            if (BST_DEBUG) printk(KERN_WARNING "pid = %d, orig_path = %s, security_pointer_index = %d entry does not exist in the table, so returning...", pid, orig_path, security_pointer_index);
            return;
        }
        bst_val = security_pid_val[index][1];
        if (bst_val == 1)
            bst_val = (bst_val + 2) * 2;
        else {
            bst_val = 0;
        }
        security_pid_val[index][1] = bst_val;
        if (BST_DEBUG) printk(KERN_WARNING "pid = %d, orig_path = %s, index = %d, bst_val = %d",pid, orig_path, index, bst_val);
    }
    else if (!strncmp("/system/xbin/mount.vboxsf", orig_path, strlen("/system/xbin/mount.vboxsf"))) {
        index = bst_find_index_from_pid(pid);
        if (index == -1) {
            if (BST_DEBUG) printk(KERN_WARNING "pid = %d, orig_path = %s, security_pointer_index = %d entry does not exist in the table, so returning...", pid, orig_path, security_pointer_index);
            return;
        }
        bst_val = security_pid_val[index][1];
        if (bst_val == 6)
            bst_val = (bst_val + 3) * 3;
        else {
            bst_val = 0;
        }
        security_pid_val[index][1] = bst_val;
        if (BST_DEBUG) printk(KERN_WARNING "pid = %d, orig_path = %s, index = %d, bst_val = %d",pid, orig_path, index, bst_val);
    }
}

/*
 * This is top level function that checks whether access to a particular file should be allowed or not for
 * different system call or not. Possible return values are:
 * NO_CHANGE : if filename is not altered,
 * REDIRECT_TO_GIVEN_FILE : when filename is redirected to some other path that is present
 * REDIRECT_NON_EXISTENT_PATH : when filename is redirected to non existent file
 * REDIRECT_PERMISSION_DENIED_PATH : when file exists but app don't have sufficient permissions to access the file
 */
return_v bst_hook_file(const char __user *filename, int follow_link)
{
    struct filename *tmp = NULL;
    int old_filename_length = 0;
    int new_filename_length = 0;
    struct task_struct *task = current;
    int status = 0;
    return_v ret = NO_CHANGE;
    kuid_t uid = current_uid();

    if (uid.val < 10000)
        return ret;

    tmp = getname(filename);
    if (!IS_ERR_OR_NULL(tmp) && tmp->name != NULL) {
        old_filename_length = strlen(tmp->name);
        ret = __bst_hook_file(tmp, filename, follow_link);
        if (ret == REDIRECT_TO_GIVEN_FILE) {
            new_filename_length = strlen(tmp->name);
            if (clear_user((char __user *)filename, old_filename_length)) {
		ret = NO_CHANGE;
                goto error;
	    }

            status = copy_to_user((char __user *)filename, tmp->name, (old_filename_length <= new_filename_length ? old_filename_length : new_filename_length + 1));
            if (status) {
                printk(KERN_WARNING "copy_to_user failed for: task: %s (%d) uid is: %d redirect path: %s, status: %d\n",task->comm, task->pid, uid.val, tmp->name, status);
                ret = NO_CHANGE;
                goto error;
            }
        }
    }

error:
    if (!IS_ERR_OR_NULL(tmp)) {
        putname(tmp);
        tmp = NULL;
    }
    return ret;
}

bool bst_calling_pkg_starts_with(const char *target_str) {
	kuid_t uid = current_uid();
	char *calling_pkg = NULL;
	bool contains = false;

	if (uid.val < 10000) {
		return false;
	}

	calling_pkg = get_pkgname_from_cmdline(-1);
	if (calling_pkg != NULL && strncmp(calling_pkg, target_str, strlen(target_str)) == 0) {
		contains = true;
	}

	if (calling_pkg) {
		kfree(calling_pkg);
	}
	calling_pkg = NULL;

	return contains;
}

inline bool bst_str_ends_with(const char *str, const char *end) {
    if (str != NULL && end != NULL
        && strlen(str) >= strlen(end) && strlen(end) != 0
        && strncmp(&str[strlen(str) - strlen(end)], end, strlen(end)) == 0) {
            return true;
    }
    return false;
}

static inline unsigned long bst_strncpy_from_user(char dst[], const char __user * src, unsigned long dstlen) {
	long len;
    if (dstlen == 0) return 0;
    len = strncpy_from_user(dst, src, (long)dstlen);
    if (len < 0 || len >= dstlen) len = 0;
    dst[len] = 0;
    return len;
}

static bool bst_is_netflix_detect_thread(void) {
    char pkgname[TASK_COMM_LEN] = {'\0', };
    char parent_pkgname[TASK_COMM_LEN] = {'\0', };
    bool matched;

    get_task_comm(pkgname, current);
    get_task_comm(parent_pkgname, current->group_leader);
    matched = (bst_str_ends_with(parent_pkgname, "GP.ProjectDesta") && !strcmp(pkgname, "nfagent"))
                    || (bst_str_ends_with(parent_pkgname, "ix.NGP.TerraNil") && !strcmp(pkgname, "nfagent"));
    return matched;
}

/* Internal function to check whether access to a particular file should be allowed or not. Possible return values are:
 * NO_CHANGE : if filename is not altered,
 * REDIRECT_TO_GIVEN_FILE : when filename is redirected to some other path that is present
 * REDIRECT_NON_EXISTENT_PATH : when filename is redirected to non existent file
 * REDIRECT_PERMISSION_DENIED_PATH : when file exists but app don't have sufficient permissions to access the file
 */
return_v __bst_hook_file(struct filename *tmp, const char __user *filename, int follow_link)
{
    file_access is_allowed = ALLOW_ALL;
    char *orig_path = NULL, *res = NULL, *buf = NULL;
    int error = -1;
    struct kstat stat;
    int num_cpus = -1;
    return_v retval = NO_CHANGE;
    kuid_t uid = current_uid();
    int flag = 0;
    char *calling_pkg = NULL;
    int i = 0;

    // for apps with uid < 10000, don't do any hacks...return rightaway.
    if (uid.val < 10000)
        return retval;

    if (IS_ERR_OR_NULL(tmp) || tmp->name == NULL)
        return retval;

    calling_pkg = get_pkgname_from_cmdline(-1);
    if (calling_pkg != NULL && (!strncmp(calling_pkg, BST_HOOKS_BYPASS_PACKAGE_1, strlen(calling_pkg)) ||
        (!strncmp(calling_pkg, BST_HOOKS_BYPASS_PACKAGE_2, strlen(calling_pkg))))) {
        goto out;
    }

    orig_path = (char *)tmp->name;

    if (!follow_link)
        flag = AT_SYMLINK_NOFOLLOW;

    if (strstr(orig_path,"/./") || strstr(orig_path,"/../") || strstr(orig_path,"//")) {
        buf = kzalloc(strlen(orig_path) + 1, GFP_KERNEL);
        if (buf == NULL) {
            printk(KERN_WARNING "memory allocation failed for buffer %s", orig_path);
        } else
            res = realpath(orig_path, buf);

        if (res) {
            if (BST_DEBUG) printk(KERN_WARNING "changing file name from '%s' to '%s'", orig_path, buf);
            orig_path = buf;
        }
    }

    if (calling_pkg && !strncmp(calling_pkg, "com.Level5.YWP", sizeof("com.Level5.YWP")-1)) {
        if (bst_str_starts_with(orig_path, "/data/downloads/gg.now.accounts")) {
            retval = redirect_to_random_file(tmp, DO_NOT_ALLOW_ANY);
            goto out;
        }
    }

    if (calling_pkg &&
            (!strncmp(calling_pkg, "com.netflix.NGP.ProjectDesta", sizeof("com.netflix.NGP.ProjectDesta")-1) ||
            !strncmp(calling_pkg, "com.netflix.NGP.TerraNil", sizeof("com.netflix.NGP.TerraNil")-1))) {
        static pid_t s_netflix_pid = -1;
        static bool s_start_detect = false;

        if (!strcmp(orig_path, "/dev/bst_gps")) {
            pid_t cur_pid = pid_nr(task_tgid(current));
            if (s_netflix_pid == -1 || s_netflix_pid != cur_pid) {
                s_netflix_pid = cur_pid;
                s_start_detect = false;

                if (bst_is_netflix_detect_thread()) {
                    s_start_detect = true;
                }
            }
        }

        if (s_start_detect) {
            if (!strcmp(orig_path, "/dev/bstpgaipc")
                    || !strcmp(orig_path, "/etc/mounts")
                    || !strcmp(orig_path, "/system/etc/public.libraries.txt")
                    || !strcmp(orig_path, "/data/downloads/.dp/apps.xml")
                    || bst_str_starts_with(orig_path, "/data/downloads/.xb/bstk")
                    || bst_str_starts_with(orig_path, "/mnt/windows")
                    || bst_str_ends_with(orig_path, "libhoudini.so")
                    ) {
                if (bst_is_netflix_detect_thread()) {
                    if (bst_str_ends_with(orig_path, "libhoudini.so")) {
                        s_start_detect = false;
                    }

                    retval = redirect_to_random_file(tmp, DO_NOT_ALLOW_ANY);
                    goto out;
                }
            }
        }
    }

    if (calling_pkg && !strncmp(calling_pkg, "com.mujoysg.luna", sizeof("com.mujoysg.luna")-1)) {
        if (!strcmp(orig_path, "/data/user/0/com.mujoysg.luna/.lebiansdk/libassetsonly/liblbfb_x86.so")) {
            strcpy((char *)tmp->name, "/data/user/0/com.mujoysg.luna/.lebiansdk/libassetsonly/liblbfb.so");
            retval = REDIRECT_TO_GIVEN_FILE;
            goto out;
        }
    }

    // ROB-10299 Game "com.racoondigi.jqhw(街頭對決)" crashes.
    if (calling_pkg && !strncmp(calling_pkg, "com.racoondigi.jqhw", sizeof("com.racoondigi.jqhw")-1)) {
        if (!strcmp(orig_path, "/proc/bus/input/devices")) {
		bool matched;
            char pkgname[TASK_COMM_LEN] = {'\0', };
            char parent_pkgname[TASK_COMM_LEN] = {'\0', };

            get_task_comm(pkgname, current);
            get_task_comm(parent_pkgname, current->group_leader);
            // Detect thread named Thread-n created by parent thread main, we should filter it
            matched = bst_str_starts_with(parent_pkgname, "racoondigi.jqhw") && bst_str_starts_with(pkgname, "Thread-");
            if (matched) {
                kfree(calling_pkg);
                if (buf) {
                    kfree(buf);
                    buf = NULL;
                }
                // not return. exit thread ...
                do_exit(0);
            }
        }
    }

    // ROB-7292 App "com.happyelements.AndroidAnimal(开心消消乐®)" crashes on launching
    // ROB-9223 App "com.m4399.gamecenter" crashes on Pie64 and Android11 engines.
    if (calling_pkg
        && (!strncmp(calling_pkg, "com.m4399.gamecenter", sizeof("com.m4399.gamecenter")-1)
        || !strncmp(calling_pkg, "com.happyelements.AndroidAnimal", sizeof("com.happyelements.AndroidAnimal")-1))) {
        if (!strcmp(orig_path, "/system/lib64/arm64/nb/libart.so")) {
            retval = redirect_to_random_file(tmp, DO_NOT_ALLOW_ANY);
            goto out;
        }
    }

    // ROB-7782 Bigo Live crashing in N32 post recent app update
    if (calling_pkg && !strncmp(calling_pkg, "sg.bigo.live", sizeof("sg.bigo.live")-1)) {
        if (!strcmp(orig_path, "/system/bin/linker64")) {
            retval = redirect_to_given_file(tmp, BST_LIB_ARM_LINKER_PATH64);
            goto out;
        }
    }

    if (calling_pkg && (bst_str_starts_with(calling_pkg, "com.asia.arrival")
        || bst_str_starts_with(calling_pkg, "com.japan.arrival"))) {
        if (filename && !strncmp(filename, "/system/bin/sh", strlen("/system/bin/sh"))) {
            retval = return_perm_denied_path(tmp, DO_NOT_ALLOW_ANY);
            goto out;
        }
    }

    if (calling_pkg && bst_str_starts_with(calling_pkg, "com.dgames.g85002002.google")) {
        if (bst_str_starts_with(orig_path, "system/xbin/bstk") || bst_str_starts_with(orig_path, "boot/bst")) {
            retval = redirect_to_random_file(tmp, DO_NOT_ALLOW_ANY);
            goto out;
        }
        if (!strcmp(orig_path, "/system/bin/linker64")) {
            retval = redirect_to_given_file(tmp, BST_LIB_ARM_LINKER_PATH64);
            goto out;
        }
    }

    //BS4-12323: AppSealing kill app after reading the file, temporary terminate the thread.
    if (calling_pkg && !strcmp(orig_path, "/system/etc/hosts")) {
#define STARTS_WITH(str, pat) (strncmp(str, pat, sizeof(pat) - 1) == 0)
        const bool matched = STARTS_WITH(calling_pkg, "com.wemade.mir4");
#undef STARTS_WITH
        if (matched) {
            kfree(calling_pkg);
            if (buf) {
                kfree(buf);
                buf = NULL;
            }
            // not return. exit thread ...
            do_exit(0);
        }
    }

    // ROB-6573 emulator fix launch playstation app crash issue
    if (calling_pkg && !strncmp(calling_pkg, "com.scee.psxandroid", sizeof("com.scee.psxandroid")-1)) {
        if (!strncmp(orig_path, "/data/app/", sizeof("/data/app/")-1) && strstr(orig_path,"libjscexecutor.so")) {
            retval = redirect_to_random_file(tmp, DO_NOT_ALLOW_ANY);
            goto out;
        }
    }

    if (calling_pkg && (bst_str_starts_with(calling_pkg, "com.miniclip.eightballpool"))) {
        if (bst_str_starts_with(orig_path, "/etc/mounts") 
             || bst_str_starts_with(orig_path, "/data/downloads/.dp/apps.xml")
             || bst_str_starts_with(orig_path, "/data/downloads/.xb/bstk")
             || bst_str_starts_with(orig_path, "/mnt/windows")
           ) {
            retval = redirect_to_random_file(tmp, DO_NOT_ALLOW_ANY);
            goto out;
        } else if (bst_str_starts_with(orig_path, "/dev/bstpgaipc")) {
            char pkgname[TASK_COMM_LEN] = {'\0', };

            get_task_comm(pkgname, current);
            if (bst_str_starts_with(pkgname, "com.miniclip.ei")) {
                retval = redirect_to_random_file(tmp, DO_NOT_ALLOW_ANY);
                goto out;
            }
        }
    }

    if (calling_pkg && (bst_str_starts_with(calling_pkg, "com.netease.ma100") || bst_str_starts_with(calling_pkg, "com.pubg.imobile") || bst_str_starts_with(calling_pkg, "com.tencent.ig"))) {
        if (bst_str_starts_with(orig_path, "/proc/") && bst_str_ends_with(orig_path, "/maps")) {
		bool matched;
            char pkgname[TASK_COMM_LEN] = {'\0', };
            char parent_pkgname[TASK_COMM_LEN] = {'\0', };

            get_task_comm(pkgname, current);
            get_task_comm(parent_pkgname, current->group_leader);
            // Detect thread named Thread-n created by parent thread MainThread-UE4, we should filter it
            matched = bst_str_starts_with(pkgname, "Thread-") && bst_str_starts_with(parent_pkgname, "MainThread-UE4");
            if (matched) {
                retval = redirect_to_random_file(tmp, DO_NOT_ALLOW_ANY);
                goto out;
            }
        }
    }

    /* ROB-10394: fix the laggy issue */
    if (calling_pkg && (bst_str_starts_with(calling_pkg, "com.nexon.hit2tw"))) {
        char file_maps[32];
        sprintf(file_maps, "/proc/%d/maps", current->group_leader->pid);

        if (bst_str_starts_with(orig_path, file_maps)) {
            char thread_name[TASK_COMM_LEN] = {'\0', };
            char parent_thread_name[TASK_COMM_LEN] = {'\0', };
            get_task_comm(thread_name, current);
            get_task_comm(parent_thread_name, current->group_leader);

            /*
             * Detect thread named Thread-6x, and x should be larger than 2. The thread causes other threads to
             * consume extremely high CPU every minute. But we should allow Thread-61 and Thread-62 to access
             * the maps file, otherwise the app will crash.
             */
            if (bst_str_starts_with(thread_name, "Thread-6") && bst_str_starts_with(parent_thread_name, "MainThread-UE4")) {
                long thread_id = 0;
                (void)kstrtol(&thread_name[7], 10, &thread_id);
                if (thread_id > 62) {
                    retval = redirect_to_random_file(tmp, DO_NOT_ALLOW_ANY);
                    goto out;
                }
            }
        }
    }


    // ROB-6475 emulator detection com.wemade.mirmcbt
    if (calling_pkg && !strncmp(calling_pkg, "com.wemade.mirmcbt", sizeof("com.wemade.mirmcbt")-1)) {
        if (!strcmp(orig_path, "/system/lib64/arm64/nb/libc.so") ) {
            char pkgname[TASK_COMM_LEN] = {'\0', };
            char parent_pkgname[TASK_COMM_LEN] = {'\0', };

		bool matched;
            get_task_comm(pkgname, current);
            get_task_comm(parent_pkgname, current->group_leader);
            // Detect thread named Thread-n created by parent thread main, we should filter it
            matched = strcmp(parent_pkgname, "main") == 0 && strstr(pkgname, "Thread-");
            if (matched) {
                kfree(calling_pkg);
                if (buf) {
                    kfree(buf);
                    buf = NULL;
                }
                // not return. exit thread ...
                do_exit(0);
            }
        }
    }

    // ROB-9653 emulator detection com.joydo.minestrikenew
    if (calling_pkg && !strncmp(calling_pkg, "com.joydo.minestrikenew", sizeof("com.joydo.minestrikenew")-1)) {
        if (!strcmp(orig_path, "/proc/bus/input/devices") ) {
            char pkgname[TASK_COMM_LEN] = {'\0', };
            get_task_comm(pkgname, current);

            if (bst_str_starts_with(pkgname, "Thread-")){
                kfree(calling_pkg);
                if (buf) {
                    kfree(buf);
                    buf = NULL;
                }
                // not return. exit thread ...
                do_exit(0);
            }
        }
    }

    // ROB-9602 LIAPP emulator detection
    if (calling_pkg && (bst_str_starts_with(calling_pkg, "com.linecorp.LGPJCOIN")
        || bst_str_starts_with(calling_pkg, "com.playhardlab.heroes")
        || bst_str_starts_with(calling_pkg, "com.tw.mf.uamo")
        || bst_str_starts_with(calling_pkg, "com.proximabeta.mf.uamo")
        || bst_str_starts_with(calling_pkg, "com.hd.xxgjhb.and")
        || bst_str_starts_with(calling_pkg, "com.com2usholdings.arestw.android.google.tw.normal")
        || bst_str_starts_with(calling_pkg, "com.linecorp.LGTAIKO"))) {
        const bool is_path_matched = bst_str_starts_with(orig_path, "/proc/") && bst_str_ends_with(orig_path, "/maps");
        if (is_path_matched) {
            char pkgname[TASK_COMM_LEN] = {'\0', };

            get_task_comm(pkgname, current);

            if (bst_str_starts_with(pkgname, "Thread-")){
                kfree(calling_pkg);
                if (buf) {
                    kfree(buf);
                    buf = NULL;
                }
                // not return. exit thread ...
                do_exit(0);
            }
        }
    }

    if (calling_pkg && (bst_str_starts_with(calling_pkg, "com.tw.mf.uamo")
        || bst_str_starts_with(calling_pkg, "com.proximabeta.mf.uamo"))) {

        if (!strcmp(orig_path, "init.android_x86.rc") ||
            !strcmp(orig_path, "ueventd.android_x86.rc") ||
            !strcmp(orig_path, "/system/framework/x86") ||
            !strcmp(orig_path, "/sys/module/bnx2/parameters/disable_msi")) {

            char pkgname[TASK_COMM_LEN] = {'\0', };
            get_task_comm(pkgname, current);

            if (bst_str_starts_with(pkgname, "Thread-")){
                kfree(calling_pkg);
                if (buf) {
                    kfree(buf);
                    buf = NULL;
                }
                // not return. exit thread ...
                do_exit(0);
            }
        }
    }

    //ROB-10824:Terminate the thread when access "/proc/version" folder to pass emulator detection.
    if (calling_pkg && bst_str_starts_with(calling_pkg, "jp.co.nextninja.dimensions")) {
        if (!strcmp(orig_path, "/proc/version")) {
            kfree(calling_pkg);
            if (buf) {
                kfree(buf);
                buf = NULL;
            }
            do_exit(0);
        }
    }

    //ROB-11115:Terminate the thread when access "/proc/self/maps" file to pass emulator detection.
    if (calling_pkg && (bst_str_starts_with(calling_pkg, "com.ncsoft.bns219"))) {
        if (bst_str_starts_with(orig_path, "/proc/") && bst_str_ends_with(orig_path, "/maps")) {
            bool matched;
            char pkgname[TASK_COMM_LEN] = {'\0', };
            get_task_comm(pkgname, current);
            // Detect thread named Thread-n, we should filter it
            matched = bst_str_starts_with(pkgname, "Thread-");
            if (matched) {
                kfree(calling_pkg);
                if (buf) {
                    kfree(buf);
                    buf = NULL;
                }
                do_exit(0);
            }
        }
    }

    // ROB-8743 Promon shield emulator detection com.supercell.clashofclans
    if (calling_pkg && bst_is_pmf_app(calling_pkg)) {
        if (!strcmp(orig_path, "/system/lib64/arm64/nb/libandroid_runtime.so") ||
            !strcmp(orig_path, "/system/lib64/arm64/nb/libc.so") ||
            !strcmp(orig_path, "/system/lib64/arm64/nb/libdl.so") ||
            !strcmp(orig_path, "/dev/vboxguest") ||
            !strcmp(orig_path, "/dev/vboxuser")) {

            bool matched;
            char pkgname[TASK_COMM_LEN] = {'\0', };
            char parent_pkgname[TASK_COMM_LEN] = {'\0', };

            get_task_comm(pkgname, current);
            get_task_comm(parent_pkgname, current->group_leader);

            matched = pkgname[0] ? (strcmp(parent_pkgname, pkgname) == 0 && !strstr(calling_pkg, parent_pkgname))
                                            : (!!strstr(calling_pkg, parent_pkgname));
            if (matched) {
                retval = return_operation_not_perm_path(tmp, DO_NOT_ALLOW_ANY);
                goto out;
            }
        }
    }

    // BS4-12037, BS4-12488:nProtect emulator detection. Terminate the thread when openat "/proc/kallsyms" folder exactly using syscall directly.
    else if (calling_pkg && !strcmp(orig_path, "/proc/kallsyms")) {
#define STARTS_WITH(str, pat) (strncmp(str, pat, sizeof(pat) - 1) == 0)
        const bool matched = STARTS_WITH(calling_pkg, "com.com2us.triplescbt.normal.freefull.google.global.android.common") ||
            STARTS_WITH(calling_pkg, "com.com2us.ninepb3d.normal.freefull.google.global.android.common") ||
            STARTS_WITH(calling_pkg, "com.bandainamcoent.toluminaria_en") ||
            STARTS_WITH(calling_pkg, "jp.goodsmile.touhoulostword_android") ||
            STARTS_WITH(calling_pkg, "com.bandainamcoent.ninjavoltage_app") ||
            STARTS_WITH(calling_pkg, "com.bandainamcoent.toluminaria") ||
            STARTS_WITH(calling_pkg, "jp.konami.prospia") ||
            STARTS_WITH(calling_pkg, "jp.co.sonymusic.game.hinatosho") ||
            STARTS_WITH(calling_pkg, "com.square_enix.android_googleplay.dqwalkj") ||
            STARTS_WITH(calling_pkg, "com.square_enix.android_googleplay.ojinekosmpjp") ||
            STARTS_WITH(calling_pkg, "com.square_enix.android_googleplay.octopath") ||
            STARTS_WITH(calling_pkg, "jp.co.taito.magic") ||
            STARTS_WITH(calling_pkg, "com.sega.sinch") ||
            STARTS_WITH(calling_pkg, "com.linegames.uwo") ||
            STARTS_WITH(calling_pkg, "com.wemade.mir2m.thewarrior") ||
            STARTS_WITH(calling_pkg, "com.square_enix.android_googleplay.EngageKill_j") ||
            STARTS_WITH(calling_pkg, "jp.co.drecom.ggggg") ||
            STARTS_WITH(calling_pkg, "jp.colopl.wcgolf") ||
            STARTS_WITH(calling_pkg, "com.vespainteractive.KingsRaid");
#undef STARTS_WITH
        if (matched) {
            kfree(calling_pkg);
            if (buf) {
                kfree(buf);
                buf = NULL;
            }
            // not return. exit thread ...
            do_exit(0);
        }
    }
    // ROB-8043,9933:New nProtect emulator detection. Terminate the thread when openat "/proc/consoles" or "/proc/version" folder exactly using syscall directly.
    else if (calling_pkg && (!strcmp(orig_path, "/proc/consoles") || !strcmp(orig_path, "/proc/version"))) {
#define STARTS_WITH(str, pat) (strncmp(str, pat, sizeof(pat) - 1) == 0)
        const bool matched = STARTS_WITH(calling_pkg, "com.linegames.udg") ||
            STARTS_WITH(calling_pkg, "com.com2us.minigame.android.google.global.normal") ||
            STARTS_WITH(calling_pkg, "com.starmakerinteractive.starmaker") ||
            STARTS_WITH(calling_pkg, "com.albiononline") ||
            STARTS_WITH(calling_pkg, "com.linegames.uwo");
#undef STARTS_WITH
        if (matched) {
           struct task_struct *task = get_taskstruct_from_pid(current->pid);
           char pkgname[sizeof(task->comm)] = {'\0', };
           char parent_pkgname[sizeof(task->comm)] = {'\0', };
           pid_t tgid = task_tgid_nr(task);
           struct task_struct *p_task = get_taskstruct_from_pid(tgid);

           get_task_comm(pkgname, current);
           get_task_comm(parent_pkgname, p_task);

           if (strstr(pkgname, parent_pkgname) == NULL) {
               kfree(calling_pkg);
               if (buf) {
                   kfree(buf);
                   buf = NULL;
               }
               // not return. exit thread ...
               do_exit(0);
           }
       }
   }

    // Case ROB-7833 ROB-7135 temp fix to make riot game treat as root mode
    else if (calling_pkg &&
            (!bst_strncmp(orig_path, "/system/sd/xbin/su", strlen("/system/sd/xbin/su")) ||
             !bst_strncmp(orig_path, "/sbin/su", strlen("/sbin/su")) ||
             !bst_strncmp(orig_path, "/system/bin/failsafe/su", strlen("/system/bin/failsafe/su")) ||
             !bst_strncmp(orig_path, "/data/local/bin/su", strlen("/data/local/bin/su")) ||
             !bst_strncmp(orig_path, "/system/xbin/su", strlen("/system/xbin/su")) ||
             !bst_strncmp(orig_path, "/data/local/su", strlen("/data/local/su")))) {
        const char *riot_pkgnames[] = {
            "com.riotgames.league.wildrift",
            "com.riotgames.legendsofruneterra"
        };
        for (i = 0; i < (sizeof(riot_pkgnames)/sizeof(riot_pkgnames[0])); i++) {
            const char *loop_pkgname = riot_pkgnames[i];
            if (!strncmp(calling_pkg, loop_pkgname, strlen(loop_pkgname))) {
                retval = redirect_to_given_file(tmp, BST_ROOTED_SU_REALPATH);
                goto out;
            }
        }
    }

    //ROB-3512: temp fix to make codm treat bluestacks as a Tencent emulator
    //ROB-6554: add package name to fake as Tencent emulator to pass emulator detection
    if (calling_pkg) {
        char *codm_pkgnames[] = {
            "com.activision.callofduty.shooter",
            "com.garena.game.codm",
            "com.tencent.tmgp.kr.codm",
            "com.tencent.tmgp.cod",
            "com.vng.codmvn",
            "com.ea.gp.apexlegendsmobilefps",
            "com.levelinfinite.apexlegendsmobile",
            "com.tw.fivexgames.apexlegendsmobile"
        };

        for (i = 0; i < (sizeof(codm_pkgnames)/sizeof(codm_pkgnames[0])); i++) {
            char *loop_pkgname = codm_pkgnames[i];
            if (!strncmp(calling_pkg, loop_pkgname, strlen(loop_pkgname)) &&
                (!bst_strncmp(orig_path, "/init.vbox86.rc", strlen("/init.vbox86.rc")) ||
                !bst_strncmp(orig_path, "/fstab.vbox86", strlen("/fstab.vbox86")) ||
                !bst_strncmp(orig_path, "/ueventd.vbox86.rc", strlen("/ueventd.vbox86.rc")) ||
                !bst_strncmp(orig_path, "/dev/socket/genyd", strlen("/dev/socket/genyd")) ||
                !bst_strncmp(orig_path, "/dev/virtpipe-sec", strlen("/dev/virtpipe-sec")) ||
                !bst_strncmp(orig_path, "/sys/class/usbmon/usbmon1", strlen("/sys/class/usbmon/usbmon1")) ||
                !bst_strncmp(orig_path, "/data/data/com.tencent.tinput", strlen("/data/data/com.tencent.tinput")) ||
                !bst_strncmp(orig_path, "/system/bin/androVM-prop", strlen("/system/bin/androVM-prop")) ||
                !bst_strncmp(orig_path, "/system/bin/mount.tboxsf", strlen("/system/bin/mount.tboxsf")) ||
                !bst_strncmp(orig_path, "/system/bin/androVM-vbox-sf", strlen("/system/bin/androVM-vbox-sf")) ||
                !bst_strncmp(orig_path, "/system/bin/vinput_seamless", strlen("/system/bin/vinput_seamless")) ||
                !bst_strncmp(orig_path, "/system/xbin/su", strlen("/system/xbin/su")) ||
                !bst_strncmp(orig_path, "/system/lib/egl/libEGL_tencent.so", strlen("/system/lib/egl/libEGL_tencent.so")) ||
                !bst_strncmp(orig_path, "/system/lib/egl/libGLESv1_CM_tencent.so", strlen("/system/lib/egl/libGLESv1_CM_tencent.so")) ||
                !bst_strncmp(orig_path, "/system/lib/egl/libGLESv2_tencent.so", strlen("/system/lib/egl/libGLESv2_tencent.so")) ||
                !bst_strncmp(orig_path, "/system/lib/hw/audio.primary.vbox86.so", strlen("/system/lib/hw/audio.primary.vbox86.so")) ||
                !bst_strncmp(orig_path, "/system/lib/hw/camera.vbox86.so", strlen("/system/lib/hw/camera.vbox86.so")) ||
                !bst_strncmp(orig_path, "/system/lib/hw/gps.vbox86.so", strlen("/system/lib/hw/gps.vbox86.so")) ||
                !bst_strncmp(orig_path, "/system/lib/hw/gralloc.vbox86.so", strlen("/system/lib/hw/gralloc.vbox86.so")) ||
                !bst_strncmp(orig_path, "/system/lib/hw/sensors.vbox86.so", strlen("/system/lib/hw/sensors.vbox86.so")) ||
                !bst_strncmp(orig_path, "/system/lib/libTX_GLESv1_enc.so", strlen("/system/lib/libTX_GLESv1_enc.so")) ||
                !bst_strncmp(orig_path, "/system/lib/libTX_GLESv2_enc.so", strlen("/system/lib/libTX_GLESv2_enc.so")) ||
                !bst_strncmp(orig_path, "/system/lib/libTX_OpenglSystemCommon.so", strlen("/system/lib/libTX_OpenglSystemCommon.so")) ||
                !bst_strncmp(orig_path, "/system/lib/libTX_renderControl_enc.so", strlen("/system/lib/libTX_renderControl_enc.so")) ||
                !bst_strncmp(orig_path, "/system/lib/libgenyd.so", strlen("/system/lib/libgenyd.so")) ||
                !bst_strncmp(orig_path, "/system/lib/libhotx612.so", strlen("/system/lib/libhotx612.so")) ||
                !bst_strncmp(orig_path, "/system/lib/libhotx711.so", strlen("/system/lib/libhotx711.so")) ||
                !bst_strncmp(orig_path, "/system/lib/libhoudini_408p.so", strlen("/system/lib/libhoudini_408p.so")) ||
                !bst_strncmp(orig_path, "/system/lib/arm711", strlen("/system/lib/arm711")) ||
                !bst_strncmp(orig_path, "/system/lib/arm612", strlen("/system/lib/arm612")) ||
                !bst_strncmp(orig_path, "/system/usr/keylayout/androVM_Virtual_Input.kl", strlen("/system/usr/keylayout/androVM_Virtual_Input.kl")) ||
                !bst_strncmp(orig_path, "/system/app/tinput", strlen("/system/app/tinput")) ||
                !bst_strncmp(orig_path, "/system/app/SoundRecorder", strlen("/system/app/SoundRecorder")) ||
                !bst_strncmp(orig_path, "/system/app/LauncherEx", strlen("/system/app/LauncherEx")) ||
                !bst_strncmp(orig_path, "/vendor/etc/init/hw/init.tenc.rc", strlen("/vendor/etc/init/hw/init.tenc.rc")))
            ) {
                retval = REDIRECT_RETURN_OK;
                goto out;
            }
        }
    }

    //ROB-11546 com.gof.global emulator detection
    if (calling_pkg && !strncmp(calling_pkg, "com.gof.global", sizeof("com.gof.global")-1)) {
        if (bst_str_starts_with(orig_path, "system/xbin/bstk") || bst_str_starts_with(orig_path, "boot/bst")) {
            retval = redirect_to_random_file(tmp, DO_NOT_ALLOW_ANY);
            goto out;
        }
        else if (!strcmp(orig_path, "/system/bin/linker64") || !strcmp(orig_path, "/system/bin/linker")) {
            retval = redirect_to_given_file(tmp, BST_LIB_ARM_LINKER_PATH64);
            goto out;          
        }
    }

    if (bst_trie_state == NOT_INITIALIZED) {
        if (BST_DEBUG) printk(KERN_WARNING "initializing trie\n");
        bst_init_path_trie();
        if (BST_DEBUG) printk(KERN_WARNING "trie initialized\n");
    }

    if (bst_trie_state == INITIALIZED && !is_trie_member(orig_path)) {
        goto out;
    }

    if (!strcmp(orig_path, CHROME_TABS_PATH) || !strcmp(orig_path, CHROME_TABS_PATH_FOR_WRITE)) {
        retval = redirect_to_given_file(tmp, CHROME_TABS_MODIFIED_PATH);
        goto out;
    }

    error = bst_vfs_fstatat(AT_FDCWD, filename, &stat, flag);

    if (!error && stat.uid.val == uid.val) {
        goto out;
    }

    // checking num_online_cpus if this number is less than 2, we redirect apps to a file which says there are 2 cpus
    // if they enquire about /sys/devices/system/cpu/present or possbile or online
    num_cpus = num_online_cpus();
    // Checking if path is of ARM emulated library which doesn't exist for us, if so redirecting them to alternative path
    if (!bst_strncmp(orig_path, BST_ARM_EMUL_PATH, strlen(BST_ARM_EMUL_PATH))) {
        retval = change_arm_emul_path(tmp);
    }
    // redirecting apps to /system/etc/possible if num_online_cpus is less than 2 and if path contains /sys/devices/system/cpu/possible
    // or /sys/devices/system/cpu/present or /sys/devices/system/cpu/online
    else if (num_cpus < 2 &&
            (!bst_strncmp(orig_path, BST_CPU_POSSIBLE_PATH , strlen(BST_CPU_POSSIBLE_PATH)) ||
             !bst_strncmp(orig_path, BST_CPU_PRESENT_PATH, strlen(BST_CPU_PRESENT_PATH)) ||
             !bst_strncmp(orig_path, BST_CPU_ONLINE_PATH, strlen(BST_CPU_ONLINE_PATH)))) {
        retval = redirect_to_given_file(tmp, BST_CPU_POSSIBLE_MODIFIED_PATH);
    }
    // if path contains /sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq or other freq paths
    // redirect to /system/etc/cpufreq"
    else if (!bst_strncmp(orig_path, BST_CPU_PROP_PATH_PREFIX, strlen(BST_CPU_PROP_PATH_PREFIX)) &&
            !bst_strncmp(orig_path + sizeof(BST_CPU_PROP_PATH_PREFIX) - 1, BST_CPU_COMMON_FREQ_PART, strlen(BST_CPU_COMMON_FREQ_PART))) {
        retval = change_cpu_prop_freq_path(tmp);
    }
    // redirecting /proc/cpuinfo read to /etc/cpuinfo for apps.
    else if (num_cpus < 2 && !bst_strncmp(orig_path, BST_CPUINFO_PATH, strlen(BST_CPUINFO_PATH))) {
        retval = redirect_to_given_file(tmp, BST_MODIFIED_CPUINFO_PATH);
    }
    // redirecting /proc/ioports to /dev/null
    else if (!bst_strncmp(orig_path, BST_PROC_IOPORT_PATH, strlen(BST_PROC_IOPORT_PATH))) {
        retval = redirect_to_given_file(tmp, BST_REDIRECT_PROC_MOD_PATH);
    }
    // redirecting /sys/fs/selinux/enforce to /etc/selinux_enforce
    else if (!bst_strncmp(orig_path, BST_SE_LINUX_PATH, strlen(BST_SE_LINUX_PATH))) {
        retval = redirect_to_given_file(tmp, BST_SE_LINUX_MODIFIED_PATH);
    }
    // redirecting /system/build.prop to /data/.propfile for x86 apps and to /data/.abipropfile for arm apps.
    else if (!bst_strncmp(orig_path, BST_BUILD_PROP_PATH, strlen(BST_BUILD_PROP_PATH))) {
        retval = change_arm_build_prop_path(tmp, BST_BUILD_PROP_ABI_MODIFIED_PATH);
        if (retval == NO_CHANGE)
            retval = redirect_to_given_file(tmp, BST_BUILD_PROP_MODIFIED_PATH);
    }
    //Bug 14956: Redirecting /proc/net/unix to /system/etc/unix. Hiding adbd, bstfolded, bst-orientation entry.
    else if (!bst_strncmp(orig_path, BST_PROC_NET_UNIX_PATH, strlen(BST_PROC_NET_UNIX_PATH))) {
        retval = redirect_to_given_file(tmp, BST_MODIFIED_NET_UNIX_PATH);
    }

    // We want to hide the vbox vendor id(0x80ee) from pci devices,and vbox entries from /sys/module,
    // /sys/class/misc/,/sys/devices/virtual/misc/,/dev/vbox.
    // We also hide entries from /proc of bstid, vmid, bstfolder_exports, glport and hostsensorport.
    // Also, do not allow read of /data/.bluestacks.prop file (Bug 6460: com.netmarble.lineageII security issue).
    // BS4-12237: com.netease.XY2Pocket, emulator detection, do not allow read of /sys/kernel/debug/x86 path.
    // Add entries to bst_check_ENOENT_required if you want to hide files from all 3rd parties app(including google packages)

    else if((is_allowed = bst_check_ENOENT_required(orig_path, false)) != ALLOW_ALL) {
        if (is_allowed == DO_NOT_ALLOW_ANY) {
            if (!bst_strncmp(orig_path, BST_DEV_VBOXUSER_PATH, strlen(BST_DEV_VBOXUSER_PATH)) && _bst_is_vulkan_app())
                retval = NO_CHANGE;
            else
                retval = redirect_to_random_file(tmp, DO_NOT_ALLOW_ANY);
        } else if (is_allowed == ALLOW_GOOGLE) {
            retval = redirect_to_random_file(tmp, ALLOW_GOOGLE);
        }
    }

    //BS4-5190 - com.ActionSquare.GiganticX detecting root when returning EACCESS on /sys/module
    // Returning EPERM error when app is trying to access /sys/module.
    else if(!bst_strncmp(orig_path, BST_SYS_MODULE_PATH, strlen(BST_SYS_MODULE_PATH))) {
        retval = return_operation_not_perm_path(tmp, DO_NOT_ALLOW_ANY);
    }
    // Returning EACCES error to match the behavior with real android device
    else if(!bst_strncmp(orig_path, BST_DALVIK_CACHE_ARM_PATH, strlen(BST_DALVIK_CACHE_ARM_PATH)) ||
            !bst_strncmp(orig_path, BST_DEFAULT_BUILD_PROP_PATH, strlen(BST_DEFAULT_BUILD_PROP_PATH)) ||
            !bst_strncmp(orig_path, BST_PROC_MOD_PATH, strlen(BST_PROC_MOD_PATH)) ||
            !bst_strncmp(orig_path, BST_SYSTEM_LIB_MODULES_PATH, strlen(BST_SYSTEM_LIB_MODULES_PATH)) ||
            !bst_strncmp(orig_path, BST_LIB_MODULES_PATH, strlen(BST_LIB_MODULES_PATH)) ||
            !bst_strncmp(orig_path, BST_SYS_BUS_PCI_PATH, strlen(BST_SYS_BUS_PCI_PATH)) ||
            !bst_strncmp(orig_path, BST_SYS_CLASS_NET_WLAN0, strlen(BST_SYS_CLASS_NET_WLAN0)) ||
            !bst_strncmp(orig_path, BST_PROC_INTERRUPTS_PATH, strlen(BST_PROC_INTERRUPTS_PATH)) ||
            !bst_strncmp(orig_path, BST_PROC_BUS_PCI_PATH, strlen(BST_PROC_BUS_PCI_PATH)) ||
            !bst_strncmp(orig_path, BST_PROC_FILESYSTEMS_PATH, strlen(BST_PROC_FILESYSTEMS_PATH)) ||
            !bst_strncmp(orig_path, BST_SYS_CLASS_THERMAL, strlen(BST_SYS_CLASS_THERMAL)) ||
            !bst_strncmp(orig_path, BST_UEVENTD_RC_FILE, strlen(BST_UEVENTD_RC_FILE)) ||
            !bst_strncmp(orig_path, BST_PROC_TIMERLIST_PATH, strlen(BST_PROC_TIMERLIST_PATH)) ||
            !bst_strncmp(orig_path, BST_SYS_POWER_SUPPLY_PATH, strlen(BST_SYS_POWER_SUPPLY_PATH))) {
        retval = return_perm_denied_path(tmp, DO_NOT_ALLOW_ANY);
    }
    // Adding this check in last as file path starting with /proc/ (eg. /proc/bus/pci/) can fall into this check,and we can return NO_CHANGE
    // to a file,which has to be redirected
    else if (!bst_strncmp(orig_path, BST_PROC_PATH_PREFIX, strlen(BST_PROC_PATH_PREFIX))) {
        retval = redirect_bst_proc_listing(tmp);
    }

out:
    if (buf) {
        kfree(buf);
        buf = NULL;
    }
    if (calling_pkg) {
        kfree(calling_pkg);
        calling_pkg = NULL;
    }
    return retval;
}

/*
 * Function to hide entries from getdent and similar function calls.
 * This function can be used to hook getdents, getdents64 system call to hide specific file information.
 * Currently, we are hiding some of the proc FS entries by comparing the inode information.
 * INPUT:
 * name: name of the file like vmid (this will not provide you complete path /proc/vmid)
 * return 1 to hide file "name"
 * return 0 for no changes in result.
 */
int bst_hook_readdir(const char *name, int namlen, unsigned int inode)
{
    kuid_t uid = current_uid();
    char * calling_pkg = NULL;
    int i = 0;
    int retval = 0;
    file_access allowed_to_google;

    // for apps with uid < 10000, don't do anything, just return
    if (uid.val < 10000) {
        retval = 0;
        goto out;
    }

    // if filename is not known, don't do anything, just return
    if (IS_ERR_OR_NULL(name)) {
        retval = 0;
        goto out;
    }

    // hide entries from /proc of ioports, bstid, vmid, bstfolder_exports, glport and hostsensorport.
    // Some apps try to read this information through getdents to identify whether they are running on
    // emulator or not.
    /*
       if (!bst_strncmp(name, BST_PROC_IOPORT_PATH + strlen(BST_PROC_PATH_PREFIX), strlen(BST_PROC_IOPORT_PATH) - strlen(BST_PROC_PATH_PREFIX)) ||
       !bst_strncmp(name, BST_PROC_VMID_PATH + strlen(BST_PROC_PATH_PREFIX), strlen(BST_PROC_VMID_PATH) - strlen(BST_PROC_PATH_PREFIX)) ||
       !bst_strncmp(name, BST_PROC_BSTID_PATH + strlen(BST_PROC_PATH_PREFIX), strlen(BST_PROC_BSTID_PATH) - strlen(BST_PROC_PATH_PREFIX)) ||
       !bst_strncmp(name, BST_PROC_BSTFOLDER_EXPORTS_PATH + strlen(BST_PROC_PATH_PREFIX), strlen(BST_PROC_BSTFOLDER_EXPORTS_PATH) - strlen(BST_PROC_PATH_PREFIX)) ||
       !bst_strncmp(name, BST_PROC_GLPORT_PATH + strlen(BST_PROC_PATH_PREFIX), strlen(BST_PROC_GLPORT_PATH) - strlen(BST_PROC_PATH_PREFIX)) ||
       !bst_strncmp(name, BST_PROC_HOSTSENSORPORT_PATH + strlen(BST_PROC_PATH_PREFIX), strlen(BST_PROC_HOSTSENSORPORT_PATH) - strlen(BST_PROC_PATH_PREFIX)))
       */

    calling_pkg = get_pkgname_from_cmdline(-1);
    if (BST_DEBUG) printk(KERN_WARNING "%s:%d uid: %d, getdents for file %s , pkgname %s\n", __func__, __LINE__, uid.val, name, calling_pkg);
    if (calling_pkg == NULL ||
            (strncmp(calling_pkg, BST_HOOKS_BYPASS_PACKAGE_1, strlen(BST_HOOKS_BYPASS_PACKAGE_1)) &&
             strncmp(calling_pkg, BST_HOOKS_BYPASS_PACKAGE_3, strlen(BST_HOOKS_BYPASS_PACKAGE_3)) &&
             strncmp(calling_pkg, BST_PACKAGE_1, strlen(BST_PACKAGE_1)) &&
             strncmp(calling_pkg, BST_PACKAGE_2, strlen(BST_PACKAGE_2)) &&
             strncmp(calling_pkg, BST_PACKAGE_3, strlen(BST_PACKAGE_3)) &&
             strncmp(calling_pkg, BST_PACKAGE_4, strlen(BST_PACKAGE_4)) &&
             strncmp(calling_pkg, BST_PACKAGE_6, strlen(BST_PACKAGE_6)))) {
        // Case 13632: Hiding com.bluestacks entry under /system/priv-app from getdents results here as they
        // WILL NOT HAVE ANY ENTRY in inodes array.
        // If name is of one such package, hide it from the calling app.
        // Case 11675, 10739 FIX:
        // Hiding vbox device node entries under /dev from getdents results here.
        // This fixes security violation error 32 seen in such apps.
        // Case 14629: Hiding BlueStacks_Virtual_Touch.idc file under /system/usr/idc from getdents results.
        // This fixes Illegal program detection error.
        // Hiding all entries for which ENOENT is given from getdents.
        allowed_to_google = bst_check_ENOENT_required((char *)name, true);

        if ((allowed_to_google == DO_NOT_ALLOW_ANY) || (allowed_to_google == ALLOW_GOOGLE && strncmp(calling_pkg, BST_PACKAGE_5, strlen(BST_PACKAGE_5)))) {
            retval = 1;
            goto out;
        }

        // Calling package is neither one of our packages nor one of the android system, so hiding this file entry for app.
        for (i = 0; i < (sizeof(bst_proc_ino)/sizeof(unsigned int)); i++) {
            if (BST_DEBUG) printk(KERN_WARNING "%s:%d inode = %u bst_proc_ino[%d] = %u\n", __func__, __LINE__, inode, i, bst_proc_ino[i]);
            if (bst_proc_ino[i] == inode) {
                if (BST_DEBUG) printk(KERN_WARNING "%s:%d MATCHED inode = %u bst_proc_ino[%d] = %u\n", __func__, __LINE__, inode, i, bst_proc_ino[i]);
                retval = 1;
                goto out;
            }
        }
    }

out:
    if (calling_pkg)
        kfree(calling_pkg);

    calling_pkg = NULL;

    return retval;
}

// Helper function to hide vboxsf(windows shared folder) and boot related partition from 3rd
// party apps. Some apps like com.aniplex.fategrandorder.en, jp.gungho.pad, com.square_enix.android_googleplay.index_if
// etc are checking this information to determine whether they are running on BlueStacks
// App Player or not.
int bst_mount_helper(struct seq_file *m, struct path mnt_path, struct proc_mounts *p)
{
    const char *calling_pkg = NULL;
    char *buf = NULL;
    size_t size;
    kuid_t uid = current_uid();

    // for apps with uid < 10000, don't do anything, just return
    if (uid.val < 10000) {
        return 0;
    }

    // BS4-7516 BlackDesertM low graphics issue fix
    // Calling Helper function to get the packageName accessing the procfs entry.
    // Allowing /proc/self/mounts | /proc/mounts | /proc/<pid>/mounts to show bstfolder entry if packageName is one
    // of BDM.
    calling_pkg = get_pkgname_from_cmdline(-1);
    if (calling_pkg != NULL && !strncmp(calling_pkg, "com.pearlabyss.blackdesertm", strlen("com.pearlabyss.blackdesertm"))) {
        //printk(KERN_WARNING "%s:%d uid: %d, Showing bstfolder mounts entry for pkgname %s\n", __func__, __LINE__, uid.val, calling_pkg);
        kfree(calling_pkg);
        return 0;
    }

    if (calling_pkg)
        kfree(calling_pkg);

    // Error Code 70 Patch: Removing BstSharedFolder mount point entry from getting populated
    // in mounts procfs entry for 3rd party app process/thread. This also manages correct path
    // being return in readlinkat syscall for opened fd (instead of re-direction to /etc/mounts).
    size = seq_get_buf(m, &buf);
    if (size) {
        char *path = __d_path(&mnt_path, &p->root, buf, size);
        if (!IS_ERR_OR_NULL(path) && (strstr(path, "/windows") != NULL ||
                    strstr(path, "/boot") != NULL || strstr(path, "/tracing") != NULL ||
                strstr(path, "/binfmt_misc") != NULL || strstr(path, "/system/lib") != NULL)) {
            // skip this entry
            //printk(KERN_WARNING "%s:%d uid: %d, Hiding proc mount entry %s from pkgname %s\n", __func__, __LINE__, uid.val, path, calling_pkg);
            return SEQ_SKIP;
        }
    }
    return 0;
}

bool bst_str_starts_with(const char *source, const char *start_str) {
	if (source != NULL && start_str != NULL && strncmp(source, start_str, strlen(start_str)) == 0) {
		return true;
	}
	return false;
}

#ifdef CONFIG_PROC_FS
static int strncmp_proc_path(const char * src, char* full_path, int prefix_len, int len)
{
	char *dest = full_path + prefix_len;
	return bst_strncmp(src, dest, len);
}

/*
 * Function to get inode number of interested entries in proc filesystem. This information is later used
 * in readdir hook function to determine whether to hide proc entry for this file or not. Currently, we
 * are storing inode of ioports, bstid, vmid, bstfolder_exports, glport and hostsensorport entries in proc FS.
 * INPUT:
 * dp : current proc entry
 * dir: parent proc entry
 */
void bst_hook_proc(struct proc_dir_entry * dir, struct proc_dir_entry * dp)
{
    int i = 0;
    if (!strncmp_proc_path(dp->name, BST_PROC_IOPORT_PATH, strlen(BST_PROC_PATH_PREFIX), strlen(BST_PROC_IOPORT_PATH) - strlen(BST_PROC_PATH_PREFIX)) ||
            !strncmp_proc_path(dp->name, BST_PROC_VMID_PATH, strlen(BST_PROC_PATH_PREFIX), strlen(BST_PROC_VMID_PATH) - strlen(BST_PROC_PATH_PREFIX)) ||
            !strncmp_proc_path(dp->name, BST_PROC_BSTID_PATH, strlen(BST_PROC_PATH_PREFIX), strlen(BST_PROC_BSTID_PATH) - strlen(BST_PROC_PATH_PREFIX)) ||
            !strncmp_proc_path(dp->name, BST_PROC_BSTFOLDER_EXPORTS_PATH, strlen(BST_PROC_PATH_PREFIX), strlen(BST_PROC_BSTFOLDER_EXPORTS_PATH) - strlen(BST_PROC_PATH_PREFIX)) ||
            !strncmp_proc_path(dp->name, BST_PROC_GLPORT_PATH, strlen(BST_PROC_PATH_PREFIX), strlen(BST_PROC_GLPORT_PATH) - strlen(BST_PROC_PATH_PREFIX)) ||
            !strncmp_proc_path(dp->name, BST_PROC_HOSTSENSORPORT_PATH, strlen(BST_PROC_PATH_PREFIX), strlen(BST_PROC_HOSTSENSORPORT_PATH) - strlen(BST_PROC_PATH_PREFIX))) {
        if (BST_DEBUG) printk(KERN_WARNING "%s:%d entry created for file %s/%s (%u)\n", __func__, __LINE__, dir->name, dp->name, dp->low_ino);
        for (i = 0; i < (sizeof(bst_proc_ino)/sizeof(unsigned int)); i++) {
            if (bst_proc_ino[i] == 0) {
                if (BST_DEBUG) printk(KERN_WARNING "%s:%d entry created for file %s/%s (%u), setting bst_proc_ino[%d] to this value\n", __func__, __LINE__, dir->name, dp->name, dp->low_ino, i);
                bst_proc_ino[i] = dp->low_ino;
                break;
            }
        }
    }
}

int bst_hook_statfs(const char __user *pathname) {
    int ret = 0;
    char *pkgname;
    kuid_t uid = current_uid();

    if (uid.val < 10000) {
        return 0;
    }
    pkgname = get_pkgname_from_cmdline(-1);
    if (pkgname &&
        (bst_str_starts_with(pkgname, "com.miniclip.eightballpool") ||
         bst_str_starts_with(pkgname, "com.nexon.er") ||
         bst_str_starts_with(pkgname, "com.nexon.bnf") ||
         bst_str_starts_with(pkgname, "com.nexon.hit2"))) {
        char name[128] = {'\0', };
        const long name_len = bst_strncpy_from_user(name, pathname, sizeof(name));
        if (name_len <= 0)
            goto out;

        if (bst_str_starts_with(name, "/system/") ||
            bst_str_starts_with(name, "/boot/") ||
            bst_str_starts_with(name, BST_PROC_IRQ_BST_SENSOR_PATH) ||
            bst_str_starts_with(name, BST_PROC_IRQ_BST_PGAIPC_PATH) ||
            bst_str_starts_with(name, "/lib/arm/nb/") ||
            bst_str_starts_with(name, "/dev/bst") ||
            bst_str_starts_with(name, "/data/downloads/.xb/bstk") ||
            bst_str_starts_with(name, "/data/downloads/.dp/apps.xml") ||
            bst_str_starts_with(name, BST_SHARED_FOLDER_PATH_5) ||
            bst_str_starts_with(name, "/fstab") ||
            bst_str_starts_with(name, "/sys/module/vboxsf") ||
            bst_str_starts_with(name, "/config/sdcardfs/com.bluestacks.bsxlauncher") ||
            bst_str_ends_with(name, "com.bluestacks.home") ||
            bst_str_ends_with(name, "com.bluestacks.setting") ||
            bst_str_ends_with(name, "bstmegn") ||
            bst_str_ends_with(name, "bstorie") ||
            bst_str_ends_with(name, "libnb.so") ||
            bst_str_starts_with(name, "/data/downloads/com.bluestacks.launcher")) {
                ret = -ENOENT;
            }
    }
out:
    if (pkgname) {
        kfree(pkgname);
        pkgname = NULL;
    }
    return ret;
}

int bst_hook_modify_procmaps(char *file_name) {
    int ret = 0, i;
    char *modify_proc_maps_native_loader[] = {"com.youku.phone", "com.taobao.taobao"};
    char *modify_proc_maps_gles_bst[] = {"com.dena.a12021245", "com.dena.a12026801", "com.dena.a12020519"};
    struct task_struct *task = get_taskstruct_from_pid(current->pid);
    char pkgname[sizeof(task->comm)] = {'\0', };
    char parent_pkgname[sizeof(task->comm)] = {'\0', };
    uid_t uid = __kuid_val(task_uid(current));
    pid_t tgid = task_tgid_nr(task);
    struct task_struct *p_task = get_taskstruct_from_pid(tgid);

    get_task_comm(pkgname, current);
    get_task_comm(parent_pkgname, p_task);

    if (pkgname[0] == '\0' || !strncmp(pkgname, BST_HOOKS_BYPASS_PACKAGE_1, strlen(pkgname)))
        return ret;

    if (!strncmp(file_name, "/system/lib/libnativeloader.so", strlen("/system/lib/libnativeloader.so"))) {
        for (i = 0; i < (sizeof(modify_proc_maps_native_loader)/sizeof(modify_proc_maps_native_loader[0])); i++) {
            if ((strstr(modify_proc_maps_native_loader[i], pkgname) != NULL)
                    || (parent_pkgname[0] != '\0' && (strstr(modify_proc_maps_native_loader[i], parent_pkgname) != NULL))) {
                if (BST_DEBUG) printk(KERN_WARNING "Modifying process maps for package %s with %s, tid = %d, uid = %d, pid = %d and parent package = %s\n", pkgname, modify_proc_maps_native_loader[i], task->pid, uid, tgid, parent_pkgname);
                ret = 1;
                break;
            }
        }
    } else if (!strncmp(file_name, "/system/lib/libbinder.so", strlen("/system/lib/libbinder.so")) ||
            !strncmp(file_name, "/system/lib64/libbinder.so", strlen("/system/lib64/libbinder.so")) ||
            !strncmp(file_name, "/system/lib/egl/libGLES_bst.so", strlen("/system/lib/libGLES_bst.so")) ||
            !strncmp(file_name, "/system/lib64/egl/libGLES_bst.so", strlen("/system/lib64/egl/libGLES_bst.so"))) {
        for (i = 0; i < (sizeof(modify_proc_maps_gles_bst)/sizeof(modify_proc_maps_gles_bst[0])); i++) {
            if ((strstr(modify_proc_maps_gles_bst[i], pkgname) != NULL) ||
                    (parent_pkgname[0] != '\0' && (strstr(modify_proc_maps_gles_bst[i], parent_pkgname)))) {
                if (BST_DEBUG)  printk(KERN_WARNING "Modifying process maps for package = %s parent package = %s\n", pkgname, parent_pkgname);
                ret = 1;
                break;
            }
        }
    }
    return ret;
}

#endif


/*
#ifdef CONFIG_PROC_FS
void bst_proc_path(struct proc_dir_entry * dir, char *path) {
if (dir == NULL || !strncmp(dir->name, "/proc",4))
return;

printk(KERN_WARNING "%s:%d dir: %s path: %s (%d)\n", __func__, __LINE__, dir->name, path, strlen(path));
bst_proc_path(dir->parent, path);

printk(KERN_WARNING "%s:%d dir: %s path: %s (%d)\n", __func__, __LINE__, dir->name, path, strlen(path));
memcpy(path + strlen(path), "/", strlen("/"));
memcpy(path + strlen(path), dir->name, strlen(dir->name));
}

void bst_proc_hack(struct proc_dir_entry * dir, struct proc_dir_entry * dp) {
char path[256] = {'\0'};
if (!strncmp(dp->name,"bst", 3) || !strncmp(dp->name, "vmid", 4) || !strncmp(dp->name, "hostsensorport", strlen("hostsensorport")) || !strncmp(dp->name, "ioports", strlen("ioports")) || !strncmp(dp->name, "glport", strlen("glport"))) {
printk(KERN_WARNING "%s:%d entry created for file %s/%s (%u)\n", __func__, __LINE__, dir->name, dp->name, dp->low_ino);
memcpy(path, "/proc", strlen("/proc"));
bst_proc_path(dp, path);
printk(KERN_WARNING "%s:%d FINAL entry created for file %s (%u)\n", __func__, __LINE__, path, dp->low_ino);
}
}
#endif
*/

