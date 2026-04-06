#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const char *system_zig = "/usr/bin/zig";

static bool file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static bool dir_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static bool find_local_toolchain(char *zig_path, size_t zig_path_len, char *lib_path, size_t lib_path_len) {
    char cwd[PATH_MAX];

    if (getcwd(cwd, sizeof(cwd)) == NULL) return false;

    while (true) {
        snprintf(zig_path, zig_path_len, "%s/vendor/zig/zig-real", cwd);
        snprintf(lib_path, lib_path_len, "%s/vendor/zig-std", cwd);
        if (file_exists(zig_path) && dir_exists(lib_path)) return true;

        char *slash = strrchr(cwd, '/');
        if (slash == NULL) return false;
        if (slash == cwd) {
            cwd[1] = '\0';
            snprintf(zig_path, zig_path_len, "%s/vendor/zig/zig-real", cwd);
            snprintf(lib_path, lib_path_len, "%s/vendor/zig-std", cwd);
            return file_exists(zig_path) && dir_exists(lib_path);
        }
        *slash = '\0';
    }
}

static bool needs_lib_dir(const char *cmd) {
    return strcmp(cmd, "build") == 0 ||
        strcmp(cmd, "build-exe") == 0 ||
        strcmp(cmd, "build-lib") == 0 ||
        strcmp(cmd, "build-obj") == 0 ||
        strcmp(cmd, "test") == 0 ||
        strcmp(cmd, "run") == 0 ||
        strcmp(cmd, "fmt") == 0;
}

int main(int argc, char **argv) {
    char local_zig[PATH_MAX];
    char local_lib[PATH_MAX];

    if (find_local_toolchain(local_zig, sizeof(local_zig), local_lib, sizeof(local_lib))) {
        if (argc > 1 && needs_lib_dir(argv[1])) {
            char **args = calloc((size_t)argc + 3, sizeof(char *));
            if (args == NULL) {
                perror("calloc");
                return 1;
            }

            args[0] = local_zig;
            args[1] = argv[1];
            args[2] = "--zig-lib-dir";
            args[3] = local_lib;
            for (int i = 2; i < argc; ++i) args[i + 2] = argv[i];
            execv(local_zig, args);
            perror("execv local zig");
            free(args);
            return 1;
        }

        execv(local_zig, argv);
        perror("execv local zig");
        return 1;
    }

    execv(system_zig, argv);
    perror("execv system zig");
    return 1;
}
