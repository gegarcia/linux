/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * AppArmor security module
 *
 * This file contains AppArmor module mediation function definitions.
 *
 * Copyright 2021 Canonical Ltd.
 */

#ifndef __AA_MODULE_H
#define __AA_MODULE_H

#define AA_MAY_LOAD_DATA	AA_MAY_WRITE
#define AA_MAY_LOAD_FILE        AA_MAY_CREATE
#define AA_MAY_REQUEST		AA_MAY_APPEND
#define AA_VALID_MODULE_PERMS (AA_MAY_LOAD_DATA | AA_MAY_LOAD_FILE | \
			       AA_MAY_REQUEST)

int aa_module_from_file(struct aa_label *label, struct file *file,
			u32 request);
int aa_module_from_name(struct aa_label *label, char *name,
			u32 request, int data_type);

#endif /* __AA_MODULE_H */
