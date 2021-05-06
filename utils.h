
/*
Copyright (c) 2020 Roger Light <roger@atchoo.org>
All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.
The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.
SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
Contributors:
   Roger Light - initial implementation and documentation.
*/
#ifndef __UTILS_H_
#define __UTILS_H_

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

bool sub_acl_check(const char *acl, const char *sub);
void t_expand(const char *clientid, const char *username, const char *in, char **res);

#endif//__UTILS_H_