/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <paths.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <grp.h>
#include <termios.h>
#include <unistd.h>

#include <mtd/mtd-user.h>

#include "file.h"
#include "stringprintf.h"
#include "strings.h"
#include "android_reboot.h"
#include "iosched_policy.h"
#include "list.h"

#include <memory>

#include "devices.h"
#include "init.h"
#include "log.h"
#include "bootchart.h"
#include "signal_handler.h"
#include "init_parser.h"
#include "util.h"
#include "ueventd.h"
#include "watchdogd.h"

#include "strlcpy.h"

/* all of <cutils/sockets.h> we need */
#define ANDROID_SOCKET_ENV_PREFIX	"ANDROID_SOCKET_"
#define ANDROID_SOCKET_DIR		"/dev/socket"

static struct action *cur_action = NULL;
static struct command *cur_command = NULL;

static int have_console;
static std::string console_name = "/dev/console";
static time_t process_needs_restart;

static const char *ENV[32];

bool waiting_for_exec = false;

static int epoll_fd = -1;

void register_epoll_handler(int fd, void (*fn)()) {
    epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.ptr = reinterpret_cast<void*>(fn);
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
        ERROR("epoll_ctl failed: %s\n", strerror(errno));
    }
}

void service::NotifyStateChange(const char* new_state) {
    if ((flags & SVC_EXEC) != 0) {
        // 'exec' commands don't have properties tracking their state.
        return;
    }
}

/* add_environment - add "key=value" to the current environment */
int add_environment(const char *key, const char *val)
{
    size_t n;
    size_t key_len = strlen(key);

    /* The last environment entry is reserved to terminate the list */
    for (n = 0; n < (ARRAY_SIZE(ENV) - 1); n++) {

        /* Delete any existing entry for this key */
        if (ENV[n] != NULL) {
            size_t entry_key_len = strcspn(ENV[n], "=");
            if ((entry_key_len == key_len) && (strncmp(ENV[n], key, entry_key_len) == 0)) {
                free((char*)ENV[n]);
                ENV[n] = NULL;
            }
        }

        /* Add entry if a free slot is available */
        if (ENV[n] == NULL) {
            char* entry;
            asprintf(&entry, "%s=%s", key, val);
            ENV[n] = entry;
            return 0;
        }
    }

    ERROR("No env. room to store: '%s':'%s'\n", key, val);

    return -1;
}

void zap_stdio(void)
{
    int fd;
    fd = open("/dev/null", O_RDWR);
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
}

static void open_console()
{
    int fd;
    if ((fd = open(console_name.c_str(), O_RDWR)) < 0) {
        fd = open("/dev/null", O_RDWR);
    }
    ioctl(fd, TIOCSCTTY, 0);
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
}

static void publish_socket(const char *name, int fd)
{
    char key[64] = ANDROID_SOCKET_ENV_PREFIX;
    char val[64];

    strlcpy(key + sizeof(ANDROID_SOCKET_ENV_PREFIX) - 1,
            name,
            sizeof(key) - sizeof(ANDROID_SOCKET_ENV_PREFIX));
    snprintf(val, sizeof(val), "%d", fd);
    add_environment(key, val);

    /* make sure we don't close-on-exec */
    fcntl(fd, F_SETFD, 0);
}

void service_start(struct service *svc, const char *dynamic_args)
{
    // Starting a service removes it from the disabled or reset state and
    // immediately takes it out of the restarting state if it was in there.
    svc->flags &= (~(SVC_DISABLED|SVC_RESTARTING|SVC_RESET|SVC_RESTART|SVC_DISABLED_START));
    svc->time_started = 0;

    // Running processes require no additional work --- if they're in the
    // process of exiting, we've ensured that they will immediately restart
    // on exit, unless they are ONESHOT.
    if (svc->flags & SVC_RUNNING) {
        return;
    }

    bool needs_console = (svc->flags & SVC_CONSOLE);
    if (needs_console && !have_console) {
        ERROR("service '%s' requires console\n", svc->name);
        svc->flags |= SVC_DISABLED;
        return;
    }

    struct stat sb;
    if (stat(svc->args[0], &sb) == -1) {
        ERROR("cannot find '%s' (%s), disabling '%s'\n", svc->args[0], strerror(errno), svc->name);
        svc->flags |= SVC_DISABLED;
        return;
    }

    if ((!(svc->flags & SVC_ONESHOT)) && dynamic_args) {
        ERROR("service '%s' must be one-shot to use dynamic args, disabling\n", svc->args[0]);
        svc->flags |= SVC_DISABLED;
        return;
    }

    NOTICE("Starting service '%s'...\n", svc->name);

    pid_t pid = fork();
    if (pid == 0) {
        struct socketinfo *si;
        struct svcenvinfo *ei;

        umask(077);
        /*if (properties_initialized()) {
            get_property_workspace(&fd, &sz);
            snprintf(tmp, sizeof(tmp), "%d,%d", dup(fd), sz);
            add_environment("ANDROID_PROPERTY_WORKSPACE", tmp);
        }*/

        for (ei = svc->envvars; ei; ei = ei->next)
            add_environment(ei->name, ei->value);

        for (si = svc->sockets; si; si = si->next) {
            int socket_type = (
                    !strcmp(si->type, "stream") ? SOCK_STREAM :
                        (!strcmp(si->type, "dgram") ? SOCK_DGRAM : SOCK_SEQPACKET));
            int s = create_socket(si->name, socket_type,
                                  si->perm, si->uid, si->gid, si->socketcon);
            if (s >= 0) {
                publish_socket(si->name, s);
            }
        }

        if (svc->writepid_files_) {
            std::string pid_str = android::base::StringPrintf("%d", pid);
            for (auto& file : *svc->writepid_files_) {
                if (!android::base::WriteStringToFile(pid_str, file)) {
                    ERROR("couldn't write %s to %s: %s\n",
                          pid_str.c_str(), file.c_str(), strerror(errno));
                }
            }
        }

        if (svc->ioprio_class != IoSchedClass_NONE) {
            if (android_set_ioprio(getpid(), svc->ioprio_class, svc->ioprio_pri)) {
                ERROR("Failed to set pid %d ioprio = %d,%d: %s\n",
                      getpid(), svc->ioprio_class, svc->ioprio_pri, strerror(errno));
            }
        }

        if (needs_console) {
            setsid();
            open_console();
        } else {
            zap_stdio();
        }

        if (false) {
            for (size_t n = 0; svc->args[n]; n++) {
                INFO("args[%zu] = '%s'\n", n, svc->args[n]);
            }
            for (size_t n = 0; ENV[n]; n++) {
                INFO("env[%zu] = '%s'\n", n, ENV[n]);
            }
        }

        setpgid(0, getpid());

        // As requested, set our gid, supplemental gids, and uid.
        if (svc->gid) {
            if (setgid(svc->gid) != 0) {
                ERROR("setgid failed: %s\n", strerror(errno));
                _exit(127);
            }
        }
        if (svc->nr_supp_gids) {
            if (setgroups(svc->nr_supp_gids, svc->supp_gids) != 0) {
                ERROR("setgroups failed: %s\n", strerror(errno));
                _exit(127);
            }
        }
        if (svc->uid) {
            if (setuid(svc->uid) != 0) {
                ERROR("setuid failed: %s\n", strerror(errno));
                _exit(127);
            }
        }

        if (!dynamic_args) {
            if (execve(svc->args[0], (char**) svc->args, (char**) ENV) < 0) {
                ERROR("cannot execve('%s'): %s\n", svc->args[0], strerror(errno));
            }
        } else {
            char *arg_ptrs[INIT_PARSER_MAXARGS+1];
            int arg_idx = svc->nargs;
            char *tmp = strdup(dynamic_args);
            char *next = tmp;
            char *bword;

            /* Copy the static arguments */
            memcpy(arg_ptrs, svc->args, (svc->nargs * sizeof(char *)));

            while((bword = strsep(&next, " "))) {
                arg_ptrs[arg_idx++] = bword;
                if (arg_idx == INIT_PARSER_MAXARGS)
                    break;
            }
            arg_ptrs[arg_idx] = NULL;
            execve(svc->args[0], (char**) arg_ptrs, (char**) ENV);
        }
        _exit(127);
    }

    if (pid < 0) {
        ERROR("failed to start '%s'\n", svc->name);
        svc->pid = 0;
        return;
    }

    svc->time_started = gettime();
    svc->pid = pid;
    svc->flags |= SVC_RUNNING;

    if ((svc->flags & SVC_EXEC) != 0) {
        INFO("SVC_EXEC pid %d (uid %d gid %d+%zu) started; waiting...\n",
             svc->pid, svc->uid, svc->gid, svc->nr_supp_gids);
        waiting_for_exec = true;
    }

    svc->NotifyStateChange("running");
}

/* The how field should be either SVC_DISABLED, SVC_RESET, or SVC_RESTART */
static void service_stop_or_reset(struct service *svc, int how)
{
    /* The service is still SVC_RUNNING until its process exits, but if it has
     * already exited it shoudn't attempt a restart yet. */
    svc->flags &= ~(SVC_RESTARTING | SVC_DISABLED_START);

    if ((how != SVC_DISABLED) && (how != SVC_RESET) && (how != SVC_RESTART)) {
        /* Hrm, an illegal flag.  Default to SVC_DISABLED */
        how = SVC_DISABLED;
    }
        /* if the service has not yet started, prevent
         * it from auto-starting with its class
         */
    if (how == SVC_RESET) {
        svc->flags |= (svc->flags & SVC_RC_DISABLED) ? SVC_DISABLED : SVC_RESET;
    } else {
        svc->flags |= how;
    }

    if (svc->pid) {
        NOTICE("Service '%s' is being killed...\n", svc->name);
        kill(-svc->pid, SIGKILL);
        svc->NotifyStateChange("stopping");
    } else {
        svc->NotifyStateChange("stopped");
    }
}

void service_reset(struct service *svc)
{
    service_stop_or_reset(svc, SVC_RESET);
}

void service_stop(struct service *svc)
{
    service_stop_or_reset(svc, SVC_DISABLED);
}

void service_restart(struct service *svc)
{
    if (svc->flags & SVC_RUNNING) {
        /* Stop, wait, then start the service. */
        service_stop_or_reset(svc, SVC_RESTART);
    } else if (!(svc->flags & SVC_RESTARTING)) {
        /* Just start the service since it's not running. */
        service_start(svc, NULL);
    } /* else: Service is restarting anyways. */
}

static void restart_service_if_needed(struct service *svc)
{
    time_t next_start_time = svc->time_started + 5;

    if (next_start_time <= gettime()) {
        svc->flags &= (~SVC_RESTARTING);
        service_start(svc, NULL);
        return;
    }

    if ((next_start_time < process_needs_restart) ||
        (process_needs_restart == 0)) {
        process_needs_restart = next_start_time;
    }
}

static void restart_processes()
{
    process_needs_restart = 0;
    service_for_each_flags(SVC_RESTARTING,
                           restart_service_if_needed);
}

static void msg_start(const char *name)
{
    struct service *svc = NULL;
    char *tmp = NULL;
    char *args = NULL;

    if (!strchr(name, ':'))
        svc = service_find_by_name(name);
    else {
        tmp = strdup(name);
        if (tmp) {
            args = strchr(tmp, ':');
            *args = '\0';
            args++;

            svc = service_find_by_name(tmp);
        }
    }

    if (svc) {
        service_start(svc, args);
    } else {
        ERROR("no such service '%s'\n", name);
    }
    if (tmp)
        free(tmp);
}

static void msg_stop(const char *name)
{
    struct service *svc = service_find_by_name(name);

    if (svc) {
        service_stop(svc);
    } else {
        ERROR("no such service '%s'\n", name);
    }
}

static void msg_restart(const char *name)
{
    struct service *svc = service_find_by_name(name);

    if (svc) {
        service_restart(svc);
    } else {
        ERROR("no such service '%s'\n", name);
    }
}

void handle_control_message(const char *msg, const char *arg)
{
    if (!strcmp(msg,"start")) {
        msg_start(arg);
    } else if (!strcmp(msg,"stop")) {
        msg_stop(arg);
    } else if (!strcmp(msg,"restart")) {
        msg_restart(arg);
    } else {
        ERROR("unknown control msg '%s'\n", msg);
    }
}

static struct command *get_first_command(struct action *act)
{
    struct listnode *node;
    node = list_head(&act->commands);
    if (!node || list_empty(&act->commands))
        return NULL;

    return node_to_item(node, struct command, clist);
}

static struct command *get_next_command(struct action *act, struct command *cmd)
{
    struct listnode *node;
    node = cmd->clist.next;
    if (!node)
        return NULL;
    if (node == &act->commands)
        return NULL;

    return node_to_item(node, struct command, clist);
}

static int is_last_command(struct action *act, struct command *cmd)
{
    return (list_tail(&act->commands) == &cmd->clist);
}

std::string build_triggers_string(struct action *cur_action) {
    std::string result;
    struct listnode *node;
    struct trigger *cur_trigger;

    list_for_each(node, &cur_action->triggers) {
        cur_trigger = node_to_item(node, struct trigger, nlist);
        if (node != cur_action->triggers.next) {
            result.push_back(' ');
        }
        result += cur_trigger->name;
    }
    return result;
}

bool expand_command_arguments(int nargs, char** args, std::vector<std::string>* expanded_args) {
    std::vector<std::string>& strs = *expanded_args;
    strs.resize(nargs);
    strs[0] = args[0];

    return true;
}

void execute_one_command() {
    Timer t;

    if (!cur_action || !cur_command || is_last_command(cur_action, cur_command)) {
        cur_action = action_remove_queue_head();
        cur_command = NULL;
        if (!cur_action) {
            return;
        }

        std::string trigger_name = build_triggers_string(cur_action);
        INFO("processing action %p (%s)\n", cur_action, trigger_name.c_str());
        cur_command = get_first_command(cur_action);
    } else {
        cur_command = get_next_command(cur_action, cur_command);
    }

    if (!cur_command) {
        return;
    }
    int result = 0;
    std::vector<std::string> arg_strs;
    if (!expand_command_arguments(cur_command->nargs, cur_command->args, &arg_strs)) {
        result = -EINVAL;
    }
    if (result == 0) {
        std::vector<char*> args;
        for (auto& s : arg_strs) {
            args.push_back(&s[0]);
        }
        result = cur_command->func(args.size(), &args[0]);
    }
    if (klog_get_level() >= KLOG_INFO_LEVEL) {
        std::string cmd_str;
        for (int i = 0; i < cur_command->nargs; ++i) {
            if (i > 0) {
                cmd_str.push_back(' ');
            }
            cmd_str += cur_command->args[i];
        }
        std::string trigger_name = build_triggers_string(cur_action);

        std::string source;
        if (cur_command->filename) {
            source = android::base::StringPrintf(" (%s:%d)", cur_command->filename, cur_command->line);
        }

        INFO("Command '%s' action=%s%s returned %d took %.2fs\n",
             cmd_str.c_str(), trigger_name.c_str(), source.c_str(), result, t.duration());
    }
}

static int wait_for_coldboot_done_action(int nargs, char **args) {
    Timer t;

    NOTICE("Waiting for %s...\n", COLDBOOT_DONE);
    // Any longer than 1s is an unreasonable length of time to delay booting.
    // If you're hitting this timeout, check that you didn't make your
    // sepolicy regular expressions too expensive (http://b/19899875).
    if (wait_for_file(COLDBOOT_DONE, 1)) {
        ERROR("Timed out waiting for %s\n", COLDBOOT_DONE);
    }

    NOTICE("Waiting for %s took %.2fs.\n", COLDBOOT_DONE, t.duration());
    return 0;
}

/*
 * Writes 512 bytes of output from Hardware RNG (/dev/hw_random, backed
 * by Linux kernel's hw_random framework) into Linux RNG's via /dev/urandom.
 * Does nothing if Hardware RNG is not present.
 *
 * Since we don't yet trust the quality of Hardware RNG, these bytes are not
 * mixed into the primary pool of Linux RNG and the entropy estimate is left
 * unmodified.
 *
 * If the HW RNG device /dev/hw_random is present, we require that at least
 * 512 bytes read from it are written into Linux RNG. QA is expected to catch
 * devices/configurations where these I/O operations are blocking for a long
 * time. We do not reboot or halt on failures, as this is a best-effort
 * attempt.
 */
static int mix_hwrng_into_linux_rng_action(int nargs, char **args)
{
    int result = -1;
    int hwrandom_fd = -1;
    int urandom_fd = -1;
    char buf[512];
    ssize_t chunk_size;
    size_t total_bytes_written = 0;

    hwrandom_fd = TEMP_FAILURE_RETRY(
            open("/dev/hw_random", O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
    if (hwrandom_fd == -1) {
        if (errno == ENOENT) {
          ERROR("/dev/hw_random not found\n");
          /* It's not an error to not have a Hardware RNG. */
          result = 0;
        } else {
          ERROR("Failed to open /dev/hw_random: %s\n", strerror(errno));
        }
        goto ret;
    }

    urandom_fd = TEMP_FAILURE_RETRY(
            open("/dev/urandom", O_WRONLY | O_NOFOLLOW | O_CLOEXEC));
    if (urandom_fd == -1) {
        ERROR("Failed to open /dev/urandom: %s\n", strerror(errno));
        goto ret;
    }

    while (total_bytes_written < sizeof(buf)) {
        chunk_size = TEMP_FAILURE_RETRY(
                read(hwrandom_fd, buf, sizeof(buf) - total_bytes_written));
        if (chunk_size == -1) {
            ERROR("Failed to read from /dev/hw_random: %s\n", strerror(errno));
            goto ret;
        } else if (chunk_size == 0) {
            ERROR("Failed to read from /dev/hw_random: EOF\n");
            goto ret;
        }

        chunk_size = TEMP_FAILURE_RETRY(write(urandom_fd, buf, chunk_size));
        if (chunk_size == -1) {
            ERROR("Failed to write to /dev/urandom: %s\n", strerror(errno));
            goto ret;
        }
        total_bytes_written += chunk_size;
    }

    INFO("Mixed %zu bytes from /dev/hw_random into /dev/urandom",
                total_bytes_written);
    result = 0;

ret:
    if (hwrandom_fd != -1) {
        close(hwrandom_fd);
    }
    if (urandom_fd != -1) {
        close(urandom_fd);
    }
    return result;
}

static int console_init_action(int nargs, char **args)
{
    std::string console_name = "/dev/console";

    int fd = open(console_name.c_str(), O_RDWR | O_CLOEXEC);
    if (fd >= 0)
        have_console = 1;
    close(fd);

    fd = open("/dev/tty0", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        const char *msg;
            msg = "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"  // console is 40 cols x 30 lines
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "\n"
        "             A N D R O I D ";
        write(fd, msg, strlen(msg));
        close(fd);
    }

    return 0;
}

static void import_kernel_nv(const std::string& key, const std::string& value, bool for_emulator) {
    return;
}

static void process_kernel_cmdline() {
    // Don't expose the raw commandline to unprivileged processes.
    chmod("/proc/cmdline", 0440);

    import_kernel_cmdline(false, import_kernel_nv);
}

int main(int argc, char** argv) {
    if (!strcmp(basename(argv[0]), "ueventd")) {
        return ueventd_main(argc, argv);
    }

    if (!strcmp(basename(argv[0]), "watchdogd")) {
        return watchdogd_main(argc, argv);
    }

    // Clear the umask.
    umask(0);

    add_environment("PATH", _PATH_DEFPATH);

    bool is_first_stage = (argc == 1) || (strcmp(argv[1], "--second-stage") != 0);

    // Get the basic filesystem setup we need put together in the initramdisk
    // on / and then we'll let the rc file figure out the rest.
    if (is_first_stage) {
        mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755");
        mkdir("/dev/pts", 0755);
        mkdir("/dev/socket", 0755);
        mount("devpts", "/dev/pts", "devpts", 0, NULL);
        mount("proc", "/proc", "proc", 0, NULL);
        mount("sysfs", "/sys", "sysfs", 0, NULL);
    }

    // We must have some place other than / to create the device nodes for
    // kmsg and null, otherwise we won't be able to remount / read-only
    // later on. Now that tmpfs is mounted on /dev, we can actually talk
    // to the outside world.
    open_devnull_stdio();
    klog_init();
    klog_set_level(KLOG_NOTICE_LEVEL);

    NOTICE("init %s started!\n", is_first_stage ? "first stage" : "second stage");

    if (!is_first_stage) {
        // Indicate that booting is in progress to background fw loaders, etc.
        close(open("/dev/.booting", O_WRONLY | O_CREAT | O_CLOEXEC, 0000));

        //property_init();

        // If arguments are passed both on the command line and in DT,
        // properties set in DT always have priority over the command-line ones.
        process_kernel_cmdline();
    }

    // If we're in the kernel domain, re-exec init to transition to the init domain now
    // that the SELinux policy has been loaded.
    if (is_first_stage) {
        char* path = argv[0];
        char* args[] = { path, const_cast<char*>("--second-stage"), nullptr };
        if (execv(path, args) == -1) {
            ERROR("execv(\"%s\") failed: %s\n", path, strerror(errno));
            exit(-1); // panic
        }
    }

    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd == -1) {
        ERROR("epoll_create1 failed: %s\n", strerror(errno));
        exit(1);
    }

    signal_handler_init();

    init_parse_config("/etc/init.rc");

    action_for_each_trigger("early-init", action_add_queue_tail);

    // Queue an action that waits for coldboot done so we know ueventd has set up all of /dev...
    queue_builtin_action(wait_for_coldboot_done_action, "wait_for_coldboot_done");
    // ... so that we can start queuing up actions that require stuff from /dev.
    queue_builtin_action(mix_hwrng_into_linux_rng_action, "mix_hwrng_into_linux_rng");
    queue_builtin_action(console_init_action, "console_init");

    // Trigger all the boot actions to get us started.
    action_for_each_trigger("init", action_add_queue_tail);

    // Repeat mix_hwrng_into_linux_rng in case /dev/hw_random or /dev/random
    // wasn't ready immediately after wait_for_coldboot_done
    queue_builtin_action(mix_hwrng_into_linux_rng_action, "mix_hwrng_into_linux_rng");

    while (true) {
        if (!waiting_for_exec) {
            execute_one_command();
            restart_processes();
        }

        int timeout = -1;
        if (process_needs_restart) {
            timeout = (process_needs_restart - gettime()) * 1000;
            if (timeout < 0)
                timeout = 0;
        }

        if (!action_queue_empty() || cur_action) {
            timeout = 0;
        }

        bootchart_sample(&timeout);

        epoll_event ev;
        int nr = TEMP_FAILURE_RETRY(epoll_wait(epoll_fd, &ev, 1, timeout));
        if (nr == -1) {
            ERROR("epoll_wait failed: %s\n", strerror(errno));
        } else if (nr == 1) {
            ((void (*)()) ev.data.ptr)();
        }
    }

    return 0;
}
