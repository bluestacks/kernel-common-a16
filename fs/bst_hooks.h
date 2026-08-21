/*
 *  linux/fs/bst_hooks.c
 *
 *  This file contains BlueStacks specific hook functions.
 */

#define BST_DEBUG                            0

#define BST_ARM_EMUL_PATH                    "/data/system/arm_emul/lib/"

#define BST_CPU_PROP_PATH_PREFIX             "/sys/devices/system/cpu/cpu*"
#define BST_CPU_COMMON_FREQ_PART             "/cpufreq"
#define BST_CPU_MAX_FREQ_PART                "/cpuinfo_max_freq"
#define BST_CPU_MIN_FREQ_PART                "/cpuinfo_min_freq"
#define BST_CPU_CUR_FREQ_PART                "/cpuinfo_cur_freq"

#define BST_CPU_POSSIBLE_PATH                "/sys/devices/system/cpu/possible"
#define BST_CPU_PRESENT_PATH                 "/sys/devices/system/cpu/present"
#define BST_CPU_ONLINE_PATH                  "/sys/devices/system/cpu/online"

#define BST_CPU_POSSIBLE_MODIFIED_PATH       "/system/etc/possible"
#define BST_CPU_FREQ_COMMON_PATH_MODIFIED    "/system/etc/.cpu/cpu0/cpufreq"

#define BST_SYSTEM_BIN_PREFIX                "/system/bin/"
#define BST_SVC_MGR_PATH                     "/system/bin/bstsvcmgrtest"
#define BST_REPORT_PATH                      "/system/bin/bstreport"
#define BST_FOLDERD_BIN_PATH                 "/system/bin/bstfolderd"
#define BST_FOLDER_CTL_PATH                  "/system/bin/bstfolder_ctl"
#define BST_SYNCFS_PATH                      "/system/bin/bstsyncfs"
#define BST_SHUTDOWN_PATH                    "/system/bin/bstshutdown"
#define BST_IME_PATH                         "/system/bin/bstime"
#define BST_SHUTDOWN_CORE_PATH               "/system/bin/bstshutdown_core"
#define BST_LOGCAT_REDIRECTION_PATH          "/system/bin/logcat_redirection"
#define BST_MOUNT_VSF_PATH                   "/system/bin/mountvsf"

#define BST_REDIRECT_PROC_MOD_PATH           "/dev/null"

#define BST_PROC_MOD_FILESYSTEMS_PATH        "/etc/filesystems"
#define BST_MODIFIED_CPUINFO_PATH            "/etc/cpuinfo"
#define BST_SE_LINUX_MODIFIED_PATH           "/etc/selinux_enforce"
#define BST_MODIFIED_NET_UNIX_PATH           "/etc/unix"

#define BST_SE_LINUX_PATH                    "/sys/fs/selinux/enforce"

#define BST_SYS_MODULE_PATH                  "/sys/module"
#define BST_SYS_BUS_AC97_PATH                "/sys/bus/ac97"
#define BST_SYS_BUS_PCI_PATH                 "/sys/bus/pci"
#define BST_PROC_BUS_PCI_PATH                "/proc/bus/pci"
#define BST_SYS_MODULE_VBOX_PATH             "/sys/module/vbox*"
#define BST_SYS_MODULE_VIRTIO_PATH           "/sys/module/virtio*"
#define BST_SYS_CLASS_MISC_VBOX_PATH         "/sys/class/misc/vbox*"
#define BST_SYS_CLASS_MISC_BSTVMSG_PATH      "/sys/class/misc/bstvmsg"
#define BST_SYS_CLASS_NET_ETH0               "/sys/class/net/eth0"
#define BST_SYS_CLASS_NET_WLAN0              "/sys/class/net/wlan*"
#define BST_SYS_CLASS_THERMAL                "/sys/class/thermal"
#define BST_SYS_CLASS_INPUT                  "/sys/class/input"
#define BST_SYS_DEVICES_PCI_PATH             "/sys/devices/pci*"
#define BST_PCSPKR_PATH                      "/sys/devices/platform/pcspkr"
#define BST_DEVICES_VIRTUAL_MISC_VBOX_PATH   "/sys/devices/virtual/misc/vbox*"
#define BST_DEVICES_VIRTUAL_MISC_VBOXUSER_PATH   "/sys/devices/virtual/misc/vboxuser"
#define BST_DEVICES_VIRTUAL_MISC_VBOXGUEST_PATH   "/sys/devices/virtual/misc/vboxguest"
#define BST_DEVICES_VIRTUAL_MISC_BST_GPS_PATH "/sys/devices/virtual/misc/bst_gps"
#define BST_DEVICES_VIRTUAL_MISC_BST_IME_PATH "/sys/devices/virtual/misc/bst_ime"
#define BST_DEVICES_VIRTUAL_MISC_BST_PGA_PATH "/sys/devices/virtual/misc/bstpgaipc"
#define BST_DEVICES_VIRTUAL_MISC_BSTVMSG_PATH "/sys/devices/virtual/misc/bstvmsg"
#define BST_DEV_VBOX_PATH                    " "
#define BST_DEV_GPS_PATH                     "/dev/bst_gps"
#define BST_DEV_IME_PATH                     "/dev/bst_ime"
#define BST_DEV_BSTVMSG_PATH                 "/dev/bstvmsg"
#define BST_DEV_SOCKET_BSTFOLDERD_PATH       "/dev/socket/bstfolderd"
#define BST_DEV_VBOXGUEST_PATH_NAME          "vboxguest"
#define BST_DEV_VBOXUSER_PATH_NAME           "vboxuser"
#define BST_POSTUPGRADE_PATH                 "/system/bin/postupgrade"
#define BST_DEV_VBOXUSER_PATH                "/dev/vboxuser"
#define BST_SU_PATH                          "/system/xbin/bstk"
#define BST_ROOTED_SU_REALPATH               "/system/xbin/bstk/su"
#define BST_ROOTED_SU_FULLPATH               "/system/xbin/su"
#define BST_BUSYBOX_PATH                     "/system/xbin/busybox"
#define BST_DATA_DATA_BST_PATH               "/data/data/com.bluestacks*"
#define BST_DATA_APPLIB_BST_PATH             "/data/app-lib/com.bluestacks*"
#define BST_DATA_MISC_BST_PATH               "/data/misc/profiles/cur/0/com.bluestacks*"
#define BST_DATA_USER_DE_BST_PATH            "/data/user_de/0/com.bluestacks*"
#define BST_DATA_USER_BST_PATH               "/data/user/0/com.bluestacks*"
#define BST_VIRTUAL_TOUCH_IDC_PATH           "/system/usr/idc/BlueStacks_Virtual_Touch.idc"
#define BST_ARM_LIB_MARKER_FILE              "containsArmLibs.txt"

#define BST_MOUNT_BOOT_ANDROID_PATH          "/boot"

#define BST_DATA_DOWNLOADS_BST_APK_PATH      "/data/downloads/com.bluestacks*"
#define BST_DATA_PRIV_DOWNLOADS_BST_APK_PATH "/data/priv-downloads/com.bluestacks*"
#define BST_SDCARD_DATA_BST_APK_PATH         "/sdcard/Android/data/com.bluestacks*"
#define BST_SDCARD_DATA_BST_APK_PATH_2       "/storage/emulated/0/Android/data/com.bluestacks*"
#define BST_SDCARD_DATA_BST_APK_PATH_3       "/storage/sdcard/Android/data/com.bluestacks*"
#define BST_SDCARD_DATA_BST_APK_PATH_4       "/storage/sdcard0/Android/data/com.bluestacks*"
#define BST_SDCARD_DATA_BST_APK_PATH_5       "/mnt/sdcard/Android/data/com.bluestacks*"

#define BST_SYSTEM_APPS_BST_APK_PATH         "/system/app/com.bluestacks*"
#define BST_SYSTEM_PRIV_APPS_BST_APK_PATH    "/system/priv-app/com.bluestacks*"
#define BST_SYSTEM_LIB_PREFIX                "/system/lib/"
#define BST_LIB_PREFIX                       "/lib/"
#define BST_LIBGL_ES_LIB_PATH                "/system/lib/egl/libGLES_bst.so"
#define BST_LIBGL_ESV1_EMUL_LIB_PATH         "/system/lib/egl/libGLESv1_CM_emulation.so"
#define BST_LIBGL_EMUL_LIB_PATH              "/system/lib/egl/libEGL_emulation.so"
#define BST_LIBGL_ESV2_EMUL_LIB_PATH         "/system/lib/egl/libGLESv2_emulation.so"
#define BST_LIBGL_ESV1_ENC_LIB_PATH          "/system/lib/libGLESv1_enc.so"
#define BST_LIBGL_ESV2_ENC_LIB_PATH          "/system/lib/libGLESv2_enc.so"
#define BST_LIB_RENDCTRL_ENC_LIB_PATH        "/system/lib/lib_renderControl_enc.so"
#define BST_LIB_OPENGL_SYS_COMM_LIB_PATH     "/system/lib/libOpenglSystemCommon.so"
#define BST_LIB_PGA_LOGGER_LIB_PATH          "/system/lib/libPgaLogger.so"
#define BST_LIB_HW_GRALL_GOLDFISH_PATH       "/system/lib/hw/gralloc.goldfish.so"
#define BST_LIB_HW_AUDIO_X86_PATH            "/system/lib/hw/audio.primary.x86.so"
#define BST_LIB_HW_CAMERA_X86_PATH           "/system/lib/hw/camera.x86.so"
#define BST_LIB_HW_POWER_X86_PATH            "/system/lib/hw/power.x86.so"


#define BST_SYSTEM_LIB64_PREFIX                "/system/lib64/"
#define BST_LIB64_PREFIX                       "/lib64"
#define BST_LIBGL_ES_LIB_PATH64                "/system/lib64/egl/libGLES_bst.so"
#define BST_LIBGL_ESV1_EMUL_LIB_PATH64         "/system/lib64/egl/libGLESv1_CM_emulation.so"
#define BST_LIBGL_EMUL_LIB_PATH64              "/system/lib64/egl/libEGL_emulation.so"
#define BST_LIBGL_ESV2_EMUL_LIB_PATH64         "/system/lib64/egl/libGLESv2_emulation.so"
#define BST_LIBGL_ESV1_ENC_LIB_PATH64          "/system/lib64/libGLESv1_enc.so"
#define BST_LIBGL_ESV2_ENC_LIB_PATH64          "/system/lib64/libGLESv2_enc.so"
#define BST_LIB_RENDCTRL_ENC_LIB_PATH64        "/system/lib64/lib_renderControl_enc.so"
#define BST_LIB_OPENGL_SYS_COMM_LIB_PATH64     "/system/lib64/libOpenglSystemCommon.so"
#define BST_LIB_PGA_LOGGER_LIB_PATH64          "/system/lib64/libPgaLogger.so"
#define BST_LIB_HW_GRALL_GOLDFISH_PATH64       "/system/lib64/hw/gralloc.goldfish.so"
#define BST_LIB_ARM_LINKER_PATH64              "/system/lib64/arm64/linker64"

#define BST_SHARED_FOLDER_PATH               "/storage/emulated/0/windows"
#define BST_SHARED_FOLDER_PATH_1             "/mnt/sdcard/windows"
#define BST_SHARED_FOLDER_PATH_2             "/sdcard/windows"
#define BST_SHARED_FOLDER_PATH_3             "/storage/sdcard/windows"
#define BST_SHARED_FOLDER_PATH_4             "/storage/sdcard0/windows"
#define BST_SHARED_FOLDER_PATH_5             "/mnt/windows"
#define BST_SHARED_FOLDER_PATH_6             "mnt/windows"

#define BST_PACKAGE_1                        "com.bluestacks"
#define BST_PACKAGE_2                        "com.uncube"
#define BST_PACKAGE_3                        "com.pop.store"
#define BST_PACKAGE_4                        "com.android"
#define BST_PACKAGE_5                        "com.google"
#define BST_PACKAGE_6                        "com.location.provider"

#define BST_HOOKS_BYPASS_PACKAGE_1           "com.netmarble.sknightsmmo"
#define BST_HOOKS_BYPASS_PACKAGE_2           "com.eyougame.ynxxsy"
#define BST_HOOKS_BYPASS_PACKAGE_3           "com.papegames.nn4."

#define ALLOWED_PACKAGES_1                   "com.speedsoftware.rootexplorer"
#define ALLOWED_PACKAGES_2                   "com.netease.androidlauncher.release"
#define ALLOWED_PACKAGES_3                   "com.mumu.store"

#define SU_NOT_ALLOWED_PACKAGES_1            "com.ztgame.jielan"
#define SU_NOT_ALLOWED_PACKAGES_2            "com.playwith.rhm"

#define BST_BUILD_PROP_PATH                  "/system/build.prop"
#define BST_BUILD_PROP_MODIFIED_PATH         "/data/.propfile"
#define BST_DATA_BLUESTACKS_PROP_FILE        "/data/.bluestacks.prop"
#define BST_DATA_MISC_PROP_FILE              "/data/.misc.prop"
#define BST_BUILD_PROP_ABI_MODIFIED_PATH     "/data/.abipropfile"
#define BST_DEFAULT_BUILD_PROP_PATH          "/default.prop"
#define BST_DEFAULT_BUILD_PROP_MODIFIED_PATH "/data/.dfprop"
#define BST_CONF_PROP_PATH                   "/data/.bstconf.prop"

#define BST_PROC_PATH_PREFIX                 "/proc/"
#define BST_PROC_MOD_PATH                    "/proc/modules"
#define BST_PROC_FILESYSTEMS_PATH            "/proc/filesystems"
#define BST_CPUINFO_PATH                     "/proc/cpuinfo"
#define BST_PROC_VMID_PATH                   "/proc/vmid"
#define BST_PROC_BSTID_PATH                  "/proc/bstid"
#define BST_PROC_GLPORT_PATH                 "/proc/glport"
#define BST_PROC_BSTFOLDER_EXPORTS_PATH      "/proc/bstfolder_exports"
#define BST_PROC_HOSTSENSORPORT_PATH         "/proc/hostsensorport"
#define BST_PROC_INTERRUPTS_PATH             "/proc/interrupts"
#define BST_PROC_TIMERLIST_PATH              "/proc/timer_list"
#define BST_PROC_NET_UNIX_PATH               "/proc/net/unix"
#define BST_PROC_SELF_NET_UNIX_PATH          "/proc/self/net/unix"
#define BST_X86_RC_FILE_1                    "ueventd.android_x86.rc"
#define BST_X86_RC_FILE_2                    "init.android_x86.rc"
#define BST_X86_RC_FILE_3                    "fstab_sdcard.android_x86"
#define BST_X86_RC_FILE_4                    "fstab.android_x86"
#define BST_X86_RC_FILE_2_1                  "/init.android_x86.rc"
#define BST_UEVENTD_RC_FILE                  "/ueventd.rc"
#define BST_PROC_IOPORT_PATH                 "/proc/ioports"
#define BST_PROC_IRQ_20_VBOX_GUEST_PATH      "/proc/irq/20/vboxguest"
#define BST_PROC_IRQ_BST_CAMERA_PATH         "/proc/irq/16/bstcamera"
#define BST_PROC_IRQ_BST_AUDIO_PATH          "/proc/irq/17/bstaudio"
#define BST_PROC_IRQ_BST_INPUT_PATH          "/proc/irq/18/bstinput"
#define BST_PROC_IRQ_BSTVMSG_PATH            "/proc/irq/18/bstvmsg"
#define BST_PROC_IRQ_BST_PGAIPC_PATH         "/proc/irq/22/bstpgaipc"
#define BST_PROC_IRQ_BST_SENSOR_PATH         "/proc/irq/23/bstsensor"
#define BST_PROC_GLMODE_PATH                 "/proc/glmode"
#define BST_PROC_MEM_PCD_ENABLED_PATH        "/proc/sys/vm/pcd_enabled"
#define BST_PROC_MEM_PCD_PCLIMIT_PATH        "/proc/sys/vm/pcd_pclimit"
#define BST_PROC_MEM_PCR_ENABLED_PATH        "/proc/sys/vm/pcr_enabled"
#define BST_PROC_MEM_PCR_PCLIMIT_PATH        "/proc/sys/vm/pcr_pclimit"

#define BST_SYS_POWER_SUPPLY_PATH            "/sys/class/power_supply"
#define BST_SYS_MODIFIED_POWER_SUPPLY_PATH   "/etc/power_supply"

#define BST_FOLDER_JNI_LIB_PATH_1            "/system/lib/libbstfolder_jni.so"
#define BST_FOLDER_JNI_LIB_PATH_1_64         "/system/lib64/libbstfolder_jni.so"
#define BST_FOLDER_JNI_LIB_PATH_2            "/lib/libbstfolder_jni.so"
#define BST_FOLDER_JNI_LIB_PATH_2_64         "/lib64/libbstfolder_jni.so"
#define BST_DALVIK_CACHE_PATH                "/data/dalvik-cache/x86"
#define BST_DALVIK_CACHE_ARM_PATH            "/data/dalvik-cache/arm"

#define BST_SYSTEM_LIB_MODULES_PATH          "/system/lib/modules"
#define BST_LIB_MODULES_PATH                 "/lib/modules"

#define CHROME_TABS_PATH                     "/data/user/0/com.android.chrome/app_tabs/0/tab_state0"
#define CHROME_TABS_PATH_FOR_WRITE           "/data/user/0/com.android.chrome/app_tabs/0/tab_state0.new"
#define CHROME_TABS_MODIFIED_PATH            "/data/downloads/.tmp/tab_state0"

#define BST_SYS_KERNEL_DEBUG_X86_PATH        "/sys/kernel/debug/x86"

#define BST_MAX_CMDLINE_LEN                  128

struct proc_mounts;

typedef enum return_value
{
    NO_CHANGE,
    REDIRECT_TO_GIVEN_FILE,
    REDIRECT_NON_EXISTENT_PATH,
    REDIRECT_PERMISSION_DENIED_PATH,
    REDIRECT_OPERATION_NOT_PERMITTED,
    REDIRECT_RETURN_OK
} return_v;

typedef enum follow_link
{
    DO_NOT_FOLLOW_LINK,
    FOLLOW_LINK
} follow_link;

typedef enum file_access
{
    DO_NOT_ALLOW_ANY,
    ALLOW_GOOGLE,
    ALLOW_ALL,
    ALLOW_IN_AGA,
} file_access;

typedef enum list_init
{
    NOT_INITIALIZED,
    INITIALIZED,
    FAILURE
} list_init;

struct bst_pkg_tgid_uid_node {
    int tgid;
    int uid;
    char package_name[BST_MAX_CMDLINE_LEN];
} typedef bst_pkg_tgid_uid_node;

struct bst_pkg_config_pmf {
    bool ispmf;
    char pkgname[BST_MAX_CMDLINE_LEN];
} typedef bst_pkg_config_pmf;

/*
 * Trie structure for bst interested paths
 * - child node takes one level deeper in the path
 * - next node searches paths among same level
 */
struct bst_trie_node {
    char* file_name;
    bool is_end_of_path;
    struct bst_trie_node* child,* next;
} typedef bst_trie_node;

return_v bst_hook_file(const char __user *filename, int follow_link);
return_v __bst_hook_file(struct filename *tmp, const char __user *filename, int follow_link);
int bst_hook_readdir(const char *name, int namlen, unsigned int inode);
int bst_mount_helper(struct seq_file *m, struct path mnt_path, struct proc_mounts *p);
int bst_hook_statfs(const char __user *pathname);
char *get_pkgname_from_cmdline(int pid);
void bst_stat_security_hook(struct filename* tmp);
int bst_open_security_hook(struct filename* tmp);
bool bst_calling_pkg_starts_with(const char *target_str);
bool bst_str_starts_with(const char *source, const char *start_str);

static inline bool bst_current_uid_is_system(void) {
	uid_t uid = __kuid_val(current_uid());
	if (uid < 10000) {
		return true;
	}
	return false;
}

static inline bool bst_current_uid_is_user_app(void)
{
    return ! bst_current_uid_is_system();
}

#define BST_VM_ARM_EXEC        (1ull << 48)   // ref: linux/mm.h
#define BST_PROT_ARM_EXEC       0x10000       // ref: uapi/asm-generic/mman-common.h

#define BST_CALC_VM_PROT_BITS(prot) (((prot & (PROT_EXEC | BST_PROT_ARM_EXEC)) == BST_PROT_ARM_EXEC) ? BST_VM_ARM_EXEC : 0)

static inline uid_t bst_getuid(void)                  { return __kuid_val(current_uid()); }
static inline bool  bst_is_android_app_uid(uid_t uid) { return uid >= 10000; }
static inline bool  bst_is_android_app(void)          { return bst_is_android_app_uid(bst_getuid()); }

#ifdef CONFIG_PROC_FS
void bst_hook_proc(struct proc_dir_entry * dir, struct proc_dir_entry * dp);
int bst_hook_modify_procmaps(char *file_name);
#endif
