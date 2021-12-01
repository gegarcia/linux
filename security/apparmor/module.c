// SPDX-License-Identifier: GPL-2.0-only
/*
 * AppArmor security module
 *
 * This file contains AppArmor module mediation
 *
 * Copyright 2021 Canonical Ltd.
 */

#include <linux/gfp.h>
#include <linux/path.h>

#include "include/audit.h"
#include "include/module.h"
#include "include/path.h"
#include "include/policy.h"

/**
 * audit_module_mask - convert mask to permission string
 * @mask: permission mask to convert
 *
 * Returns: pointer to static string
 */
static const char *audit_module_mask(u32 mask)
{
	switch (mask) {
	case AA_MAY_LOAD_DATA:
		return "load_data";
	case AA_MAY_LOAD_FILE:
		return "load_file";
	case AA_MAY_REQUEST:
		return "request";
	}
	return "";
}

/* callback to audit module fields */
static void audit_module_cb(struct audit_buffer *ab, void *va)
{
	struct common_audit_data *sa = va;

	if (aad(sa)->request & AA_VALID_MODULE_PERMS) {
		audit_log_format(ab, " requested_mask=\"%s\"",
				 audit_module_mask(aad(sa)->request));

		if (aad(sa)->denied & AA_VALID_MODULE_PERMS) {
			audit_log_format(ab, " denied_mask=\"%s\"",
					 audit_module_mask(aad(sa)->denied));
		}
	}
}

/**
 * audit_module - handle the auditing of module operations
 * @profile: the profile being enforced  (NOT NULL)
 * @perms: the permissions computed for the request (NOT NULL)
 * @request: permissions requested
 * @name: name of object being mediated (MAY BE NULL)
 * @info: extra information message (MAY BE NULL)
 * @error: 0 if operation allowed else failure error code
 * @data_type: audit data type
 *
 * Returns: %0 or error on failure
 */
static int audit_module(struct aa_profile *profile, struct aa_perms *perms,
			u32 request, const char *name, const char *info,
			int error, int data_type)
{
	int type = AUDIT_APPARMOR_AUTO;
	DEFINE_AUDIT_DATA(sa, data_type, OP_MODULE);

	if (likely(!error)) {
		u32 mask = perms->audit;

		if (unlikely(AUDIT_MODE(profile) == AUDIT_ALL))
			mask = 0xffff;

		/* mask off perms that are not being force audited */
		request &= mask;

		if (likely(!request))
			return 0;
		type = AUDIT_APPARMOR_AUDIT;
	} else {
		/* only report permissions that were denied */
		request = request & ~perms->allow;

		if (request & perms->kill)
			type = AUDIT_APPARMOR_KILL;

		/* quiet known rejects, assumes quiet and kill do not overlap */
		if ((request & perms->quiet) &&
		    AUDIT_MODE(profile) != AUDIT_NOQUIET &&
		    AUDIT_MODE(profile) != AUDIT_ALL)
			request &= ~perms->quiet;

		if (!request)
			return error;
	}

	aad(&sa)->request = request;
	aad(&sa)->name = name;
	aad(&sa)->info = info;
	aad(&sa)->error = error;
	aad(&sa)->denied = aad(&sa)->request & ~perms->allow;

	return aa_audit(type, profile, &sa, audit_module_cb);
}


/**
 * compute_module_perms - compute module permission associated with @state
 * @dfa: dfa to match against (NOT NULL)
 * @state: state match finished in
 *
 * Returns: module permissions
 */
static struct aa_perms compute_module_perms(struct aa_dfa *dfa,
					    unsigned int state)
{
	struct aa_perms perms = {
		.allow = dfa_user_allow(dfa, state),
		.audit = dfa_user_audit(dfa, state),
		.quiet = dfa_user_quiet(dfa, state),
		.xindex = dfa_user_xindex(dfa, state),
	};

	return perms;
}


/**
 * audit_module - handle the auditing of module operations
 * @profile: the profile being enforced  (NOT NULL)
 * @perms: the permissions computed for the request (NOT NULL)
 * @request: permissions requested
 * @name: name of object being mediated (MAY BE NULL)
 * @info: extra information message (MAY BE NULL)
 * @error: 0 if operation allowed else failure error code
 * @data_type: audit data type
 *
 * Returns: %0 or error on failure
 */
static int module_perm(struct aa_profile *profile,
		       const char *name, u32 request,
		       int data_type)
{
	int error = 0;
	struct aa_perms perms = { };
	unsigned int state;

	if (profile_unconfined(profile))
		return 0;

	if (!PROFILE_MEDIATES(profile, AA_CLASS_MODULE))
		return 0;

	state = aa_dfa_match(profile->policy.dfa,
			     profile->policy.start[AA_CLASS_MODULE],
			     name);
	perms = compute_module_perms(profile->policy.dfa, state);

	if (request & ~perms.allow)
		error = -EACCES;

	return audit_module(profile, &perms, request, name, NULL,
			    error, data_type);
}

static int path_module_perm(struct aa_profile *profile,
			    const struct path *path,
			    char *buffer, u32 request)
{
	const char *name;
	const char *info = NULL;
	int error;

	if (profile_unconfined(profile))
		return 0;

	error = aa_path_name(path, profile->path_flags, buffer, &name, &info,
			     labels_profile(&profile->label)->disconnected);

	if (error) {
		return audit_module(profile, &nullperms, request, name, info,
				    error, LSM_AUDIT_DATA_NONE);
	}

	return module_perm(profile, name, request,
			   LSM_AUDIT_DATA_NONE);
}

/**
 * aa_module_from_file - handle module loading through a file
 * @label: label being enforced  (NOT NULL)
 * @file: file to validate loading permissions on (MAY BE NULL)
 * @request: permissions requested
 *
 * Returns: %0 or error on failure
 */
int aa_module_from_file(struct aa_label *label, struct file *file,
			u32 request)
{
	int error = 0;
	struct aa_profile *profile;
	char *buffer;

	if (unconfined(label)) {
		goto done;
	}

	if (!file) {
		error = -EPERM;
		error = fn_for_each(label, profile,
				    audit_module(profile, &nullperms,
						 request, NULL, NULL,
						 error, LSM_AUDIT_DATA_NONE));
		goto done;
	}

	buffer = aa_get_buffer(false);
	if (!buffer)
		return -ENOMEM;

	error = fn_for_each(label, profile,
			    path_module_perm(profile,
					     &file->f_path,
					     buffer, request));
	aa_put_buffer(buffer);
done:
	return error;
}


static int name_module_perm(struct aa_profile *profile,
			    char *name, u32 request, int data_type)
{
	if (profile_unconfined(profile))
		return 0;

	return module_perm(profile, name, request,
			   data_type);
}

/**
 * aa_module_from_file - handle module loading through a file
 * @label: label being enforced  (NOT NULL)
 * @name: name of object being mediated
 * @request: permissions requested
 * @data_type: audit data type
 *
 * Returns: %0 or error on failure
 */
int aa_module_from_name(struct aa_label *label, char *name,
			u32 request, int data_type)
{
	struct aa_profile *profile;
	int error = 0;

	if (unconfined(label)) {
		goto done;
	}

	error = fn_for_each(label, profile,
			    name_module_perm(profile, name,
					     request, data_type));
done:
	return error;
}
