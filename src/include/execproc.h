/*
 * execproc.h
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

#ifndef EXECPROC_H
#define EXECPROC_H

#define EXEC_MAX_ARGS           20
#define EXEC_CMD_NOT_FOUND      -10
#define EXEC_CMD_NOT_ROOT       -11
#define EXEC_CMD_NOT_EXECUTABLE -12
#define EXEC_PIPE_ERROR         -13
#define EXEC_FORK_ERROR         -14
#define EXEC_EXIT_ERROR         -15
#define EXEC_TOO_MANY_ARGS      -16

int execute_process(char *input, char *output, const char *cmd, const char *arg, ...);
int execute_process_args(char *input, char *output, const char *cmd, char **exec_args);
void get_exec_path(const char *fname, char *path);

#endif
