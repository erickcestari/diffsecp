#ifndef DIFFSECP_ORACLE_H
#define DIFFSECP_ORACLE_H

/* Per-input comparison with other architectures, for src/fuzz.c. Each oracle is
 * a `replay TARGET` process, a static build for another architecture under
 * qemu-user or wine, kept running for the whole fuzzing run. It reads input
 * paths on stdin and prints each transcript's digest, which must equal the
 * digest of the transcript every x86 build agreed on. `make cross` compares the
 * same digests, but only for the committed corpus. Linux only, as fuzzing is. */

#include <fcntl.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

#define ORACLE_MAX 16

struct oracle {
    const char *name;
    FILE *in;
    FILE *out;
};

static struct oracle oracles[ORACLE_MAX];
static size_t noracles;
/* The file every oracle reads the input from. */
static char oracle_input[512];
/* oracle_due picks the fraction oracle_threshold / 2^64 of the inputs, drawn
 * with xorshift64. */
static uint64_t oracle_threshold, oracle_rng;

/* Starts one process per NAME=COMMAND in spec, separated by ';', each command
 * split at spaces, to check the fraction rate of the inputs. The input file
 * goes under dir, which must be relative for wine. Returns 0, or prints why it
 * can't and returns -1. */
static int oracle_start(const char *spec, const char *dir, double rate) {
    char *entry, *save = NULL, *copy = strdup(spec);

    oracle_threshold = rate >= 1 ? UINT64_MAX : rate <= 0 ? 0 : (uint64_t)(rate * 18446744073709551616.0);
    oracle_rng = (uint64_t)getpid() << 32 | 1;

    /* A write to a process that exited would otherwise kill the fuzzer. */
    signal(SIGPIPE, SIG_IGN);
    snprintf(oracle_input, sizeof(oracle_input), "%s/%ld", dir, (long)getpid());
    mkdir(dir, 0777);
    mkdir(oracle_input, 0777);
    strncat(oracle_input, "/input", sizeof(oracle_input) - strlen(oracle_input) - 1);

    for (entry = strtok_r(copy, ";", &save); entry != NULL; entry = strtok_r(NULL, ";", &save)) {
        char *eq, *argv[64], *words = NULL;
        int to[2], from[2], argc = 0;
        posix_spawn_file_actions_t actions;
        pid_t pid;

        entry += strspn(entry, " ");
        if (entry[0] == '\0') {
            continue;
        }
        eq = strchr(entry, '=');
        if (eq == NULL || noracles == ORACLE_MAX) {
            fprintf(stderr, "diffsecp: oracle %s: expected NAME=COMMAND, at most %d\n", entry, ORACLE_MAX);
            return -1;
        }
        *eq = '\0';
        for (argv[0] = strtok_r(eq + 1, " ", &words); argv[argc] != NULL && argc < 63;) {
            argv[++argc] = strtok_r(NULL, " ", &words);
        }
        argv[argc] = NULL;
        /* Close-on-exec, so no process inherits another's pipes. */
        if (argc == 0 || pipe2(to, O_CLOEXEC) != 0 || pipe2(from, O_CLOEXEC) != 0) {
            fprintf(stderr, "diffsecp: oracle %s: no command, or no pipe\n", entry);
            return -1;
        }
        posix_spawn_file_actions_init(&actions);
        posix_spawn_file_actions_adddup2(&actions, to[0], STDIN_FILENO);
        posix_spawn_file_actions_adddup2(&actions, from[1], STDOUT_FILENO);
        if (posix_spawnp(&pid, argv[0], &actions, NULL, argv, environ) != 0) {
            fprintf(stderr, "diffsecp: oracle %s: cannot run %s\n", entry, argv[0]);
            return -1;
        }
        posix_spawn_file_actions_destroy(&actions);
        close(to[0]);
        close(from[1]);
        oracles[noracles].name = entry;
        oracles[noracles].in = fdopen(to[1], "w");
        oracles[noracles].out = fdopen(from[0], "r");
        noracles++;
    }
    return 0;
}

/* Whether this input goes to the oracles. */
static int oracle_due(void) {
    oracle_rng ^= oracle_rng << 13;
    oracle_rng ^= oracle_rng >> 7;
    oracle_rng ^= oracle_rng << 17;
    return oracle_threshold != 0 && oracle_rng <= oracle_threshold;
}

/* Runs input on every oracle. Returns the name of the first whose answer isn't
 * the reference digest, with that answer in answer; one whose process exited,
 * as when its build crashes, answers nothing. Returns NULL if all agree. */
static const char *oracle_check(const unsigned char *input, size_t len, uint64_t reference, char *answer,
                                size_t cap) {
    char expected[17];
    const char *diverged = NULL;
    int sent[ORACLE_MAX];
    size_t i;
    FILE *f = fopen(oracle_input, "wb");

    if (f == NULL || fwrite(input, 1, len, f) != len || fclose(f) != 0) {
        /* Not the input's fault, so no reproducer. */
        fprintf(stderr, "diffsecp: cannot write the oracle's input %s\n", oracle_input);
        exit(1);
    }
    for (i = 0; i < noracles; i++) {
        sent[i] = fprintf(oracles[i].in, "%s\n", oracle_input) > 0 && fflush(oracles[i].in) == 0;
    }
    snprintf(expected, sizeof(expected), "%016llx", (unsigned long long)reference);
    for (i = 0; i < noracles; i++) {
        char line[1024], *digest;

        /* Read every answer, even after a divergence, to keep the lines paired. */
        if (!sent[i] || fgets(line, sizeof(line), oracles[i].out) == NULL) {
            snprintf(line, sizeof(line), "no answer: the process exited");
        }
        line[strcspn(line, "\n")] = '\0';
        digest = strchr(line, ' ');
        if (diverged == NULL && (digest == NULL || strncmp(digest + 1, expected, 16) != 0 || digest[17] != ' ')) {
            diverged = oracles[i].name;
            snprintf(answer, cap, "%s", line);
        }
    }
    return diverged;
}

#endif /* DIFFSECP_ORACLE_H */
