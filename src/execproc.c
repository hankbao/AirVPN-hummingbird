/*
 * execproc.c
 *
 * This file is part of AirVPN's Linux/macOS OpenVPN Client software.
 * Copyright (C) 2019 AirVPN (support@airvpn.org) / https://airvpn.org
 *
 * Developed by ProMIND
 *
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Eddie. If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include "include/execproc.h"

#define INPUT_FD                  0
#define OUTPUT_FD                 1

pid_t do_execute(char *input, char *output, char *cmd, char **arg)
{
    int parent_pipe[2];
    int child_pipe[2];
    pid_t pid;

    if(cmd == NULL)
        return EXEC_CMD_NOT_FOUND;

    if(pipe(parent_pipe) == -1)
	    return EXEC_PIPE_ERROR;

    if(pipe(child_pipe) == -1)
	    return EXEC_PIPE_ERROR;

    pid = fork();

    switch(pid)
    {
        case -1:
        {
	        pid = EXEC_FORK_ERROR;
        }
	    break;

        case 0:
        {
            /* child process */

            dup2(parent_pipe[INPUT_FD], STDIN_FILENO);
            dup2(child_pipe[OUTPUT_FD], STDOUT_FILENO);

            close(parent_pipe[INPUT_FD]);
            close(child_pipe[OUTPUT_FD]);
            close(child_pipe[INPUT_FD]);
            close(parent_pipe[OUTPUT_FD]);

	        execv(cmd, arg);
        }
	    break;

        default:
        {
            /* parent process */

            close(parent_pipe[INPUT_FD]);
            close(child_pipe[OUTPUT_FD]);

            if(input != NULL)
            {
                if(write(parent_pipe[OUTPUT_FD], input, strlen(input)) == -1)
                    return -1;
            }

            close(parent_pipe[OUTPUT_FD]);

            if(output != NULL)
            {
                char c;

                while(read(child_pipe[INPUT_FD], &c, 1) != 0)
                {
                    *output = c;

                    output++;
                }

                *output = '\0';
            }

            close(child_pipe[INPUT_FD]);
        }
	    break;
    }

    return pid;
}

int execute_process(char *input, char *output, const char *cmd, const char *arg, ...)
{
    int retcode, n;
    char *exec_args[EXEC_MAX_ARGS], *vl;
    struct stat cmdinfo;
    va_list alist;
    pid_t pid;

    if(cmd == NULL)
        return EXEC_CMD_NOT_FOUND;

    if(access(cmd, F_OK) == -1 || strcmp(cmd, "") == 0)
        return EXEC_CMD_NOT_FOUND;

    if(stat(cmd, &cmdinfo) != 0)
        return EXEC_CMD_NOT_FOUND;

    if(cmdinfo.st_uid != 0)
        return EXEC_CMD_NOT_ROOT;

    if(!(cmdinfo.st_mode & S_IXUSR))
        return EXEC_CMD_NOT_EXECUTABLE;

    n = 0;
    vl = (char *)arg;

    exec_args[n++] = (char *)cmd;
    exec_args[n++] = (char *)arg;

    va_start(alist, arg);

    while(vl)
    {
	    vl = va_arg(alist, char *);

        exec_args[n++] = vl;

        if(n > EXEC_MAX_ARGS)
            return EXEC_TOO_MANY_ARGS;
    }

    va_end(alist);

    pid = do_execute(input, output, (char *)cmd, exec_args);

    if(pid < 0)
        return pid;

    if(waitpid(pid, &retcode, 0) == -1)
        retcode = EXEC_EXIT_ERROR;

    return retcode;
}

int execute_process_args(char *input, char *output, const char *cmd, char **exec_args)
{
    int retcode;
    struct stat cmdinfo;
    pid_t pid;

    if(cmd == NULL)
        return EXEC_CMD_NOT_FOUND;

    if(access(cmd, F_OK) == -1 || strcmp(cmd, "") == 0)
        return EXEC_CMD_NOT_FOUND;

    if(stat(cmd, &cmdinfo) != 0)
        return EXEC_CMD_NOT_FOUND;

    if(cmdinfo.st_uid != 0)
        return EXEC_CMD_NOT_ROOT;

    if(!(cmdinfo.st_mode & S_IXUSR))
        return EXEC_CMD_NOT_EXECUTABLE;

    pid = do_execute(input, output, (char *)cmd, (char **)exec_args);

    if(pid < 0)
        return pid;

    if(waitpid(pid, &retcode, 0) == -1)
        retcode = EXEC_EXIT_ERROR;

    return retcode;
}

void get_exec_path(const char *fname, char *path)
{
    const char *binpath[] = {"/bin/", "/usr/bin/", "/sbin/", "/usr/sbin/"};
    char fname_path[64];
    bool fname_found;
    int i, items;

    fname_found = false;
    items = sizeof(binpath) / sizeof(binpath[0]);
    strcpy(path, "");

    for(i = 0; i < items && fname_found == false; i++)
    {
        strcpy(fname_path, binpath[i]);
        strcat(fname_path, fname);

        if(access(fname_path, F_OK) != -1)
            fname_found = true;
    }

    if(fname_found == true)
        strcpy(path, fname_path);
}
