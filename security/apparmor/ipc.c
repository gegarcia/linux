// SPDX-License-Identifier: GPL-2.0-only
/*
 * AppArmor security module
 *
 * This file contains AppArmor ipc mediation
 *
 * Copyright (C) 1998-2008 Novell/SUSE
 * Copyright 2009-2017 Canonical Ltd.
 */

#include <linux/gfp.h>
#include <linux/nsproxy.h>
#include <linux/ipc_namespace.h>

#include "include/audit.h"
#include "include/capability.h"
#include "include/cred.h"
#include "include/path.h"
#include "include/policy.h"
#include "include/ipc.h"
#include "include/sig_names.h"


static inline int map_signal_num(int sig)
{
	if (sig > SIGRTMAX)
		return SIGUNKNOWN;
	else if (sig >= SIGRTMIN)
		return sig - SIGRTMIN + SIGRT_BASE;
	else if (sig < MAXMAPPED_SIG)
		return sig_map[sig];
	return SIGUNKNOWN;
}

/**
 * audit_signal_mask - convert mask to permission string
 * @mask: permission mask to convert
 *
 * Returns: pointer to static string
 */
static const char *audit_signal_mask(u32 mask)
{
	if (mask & MAY_READ)
		return "receive";
	if (mask & MAY_WRITE)
		return "send";
	return "";
}

/**
 * audit_cb - call back for signal specific audit fields
 * @ab: audit_buffer  (NOT NULL)
 * @va: audit struct to audit values of  (NOT NULL)
 */
static void audit_signal_cb(struct audit_buffer *ab, void *va)
{
	struct common_audit_data *sa = va;

	if (aad(sa)->request & AA_SIGNAL_PERM_MASK) {
		audit_log_format(ab, " requested_mask=\"%s\"",
				 audit_signal_mask(aad(sa)->request));
		if (aad(sa)->denied & AA_SIGNAL_PERM_MASK) {
			audit_log_format(ab, " denied_mask=\"%s\"",
					 audit_signal_mask(aad(sa)->denied));
		}
	}
	if (aad(sa)->signal == SIGUNKNOWN)
		audit_log_format(ab, "signal=unknown(%d)",
				 aad(sa)->unmappedsig);
	else if (aad(sa)->signal < MAXMAPPED_SIGNAME)
		audit_log_format(ab, " signal=%s", sig_names[aad(sa)->signal]);
	else
		audit_log_format(ab, " signal=rtmin+%d",
				 aad(sa)->signal - SIGRT_BASE);
	audit_log_format(ab, " peer=");
	aa_label_xaudit(ab, labels_ns(aad(sa)->label), aad(sa)->peer,
			FLAGS_NONE, GFP_ATOMIC);
}

static int profile_signal_perm(struct aa_profile *profile,
			       struct aa_label *peer, u32 request,
			       struct common_audit_data *sa)
{
	struct aa_perms perms;
	unsigned int state;

	if (profile_unconfined(profile) ||
	    !PROFILE_MEDIATES(profile, AA_CLASS_SIGNAL))
		return 0;

	aad(sa)->peer = peer;
	/* TODO: secondary cache check <profile, profile, perm> */
	state = aa_dfa_next(profile->policy.dfa,
			    profile->policy.start[AA_CLASS_SIGNAL],
			    aad(sa)->signal);
	aa_label_match(profile, peer, state, false, request, &perms);
	aa_apply_modes_to_perms(profile, &perms);
	return aa_check_perms(profile, &perms, request, sa, audit_signal_cb);
}

int aa_may_signal(struct aa_label *sender, struct aa_label *target, int sig)
{
	struct aa_profile *profile;
	DEFINE_AUDIT_DATA(sa, LSM_AUDIT_DATA_NONE, OP_SIGNAL);

	aad(&sa)->signal = map_signal_num(sig);
	aad(&sa)->unmappedsig = sig;
	return xcheck_labels(sender, target, profile,
			profile_signal_perm(profile, target, MAY_WRITE, &sa),
			profile_signal_perm(profile, sender, MAY_READ, &sa));
}

static void audit_mqueue_cb(struct audit_buffer *ab, void *va)
{
	struct common_audit_data *sa = va;

	aa_audit_perms(ab, sa, NULL, 0, NULL, AA_AUDIT_POSIX_MQUEUE_MASK);

	pr_warn("class: %d      - POSIX: %d     SYSV:%d\n", aad(sa)->ipc.type, AA_CLASS_POSIX_MQUEUE, AA_CLASS_SYSV_MQUEUE);
	/* move class into generic audit framse work */
	if (aad(sa)->ipc.type == AA_CLASS_POSIX_MQUEUE)
		audit_log_format(ab, " class=\"posix_mqueue\"");
	else if(aad(sa)->ipc.type == AA_CLASS_SYSV_MQUEUE)
		audit_log_format(ab, " class=\"sysv_mqueue\"");
	if (aad(sa)->request & AA_AUDIT_FILE_MASK) {
		audit_log_format(ab, " fsuid=%u",
				 from_kuid(&init_user_ns, aad(sa)->ipc.fsuid));
		audit_log_format(ab, " ouid=%u",
				 from_kuid(&init_user_ns, aad(sa)->ipc.ouid));
	}
	if (aad(sa)->peer) {
		audit_log_format(ab, " olabel=");
		aa_label_xaudit(ab, labels_ns(aad(sa)->label), aad(sa)->peer,
				FLAGS_NONE, GFP_ATOMIC);
	}
}

int aa_profile_mqueue_perm(struct aa_profile *profile, u32 request,
			   char *queuename, int aa_class,
			   struct common_audit_data *sa)
{
	struct aa_perms perms = { };
	unsigned int state;

	if (profile_unconfined(profile) ||
	    !PROFILE_MEDIATES(profile, aa_class))
		return 0;

	aad(sa)->label = &profile->label;
	aad(sa)->ipc.type = aa_class;
	pr_warn("setting ipc.type: %d    -   aa_class: %d\n", aad(sa)->ipc.type, aa_class);

	state = aa_dfa_match(profile->policy.dfa,
			     profile->policy.start[aa_class],
			     queuename);
	aa_compute_perms(profile->policy.dfa, state, &perms);
	aa_apply_modes_to_perms(profile, &perms);
	if (!denied_perms(&perms, request)) {
		/* early bailout sufficient perms no need to do further
		 * checks */
		return aa_check_perms(profile, &perms, request, sa,
				      audit_mqueue_cb);
	}
	/* continue check to see if we have label perms */
	//aa_label_match(profile, peer??, state false, request, &perms);
	//aa_apply_modes_to_perms(profile, &perms);

	// this will just cause failure without above label check
	return aa_check_perms(profile, &perms, request, sa, audit_mqueue_cb);
}

int aa_mqueue_from_path(char *buffer, const struct path *path,
			char **name, struct common_audit_data *sa)
{
	*name = dentry_path_raw(path->dentry, buffer, aa_g_path_max);
	if (IS_ERR(*name))
		return PTR_ERR(*name);
	if (path->mnt != current->nsproxy->ipc_ns->mq_mnt) {
		/* TODO: disconnected path detection */
		pr_warn("apparmor mqueue disconnected TODO\n");
	}

	aad(sa)->name = *name;
	return 0;
}

/* mqueue - no label caching test */
int aa_mqueue_perm(const char *op, struct aa_label *label,
		   const struct path *path, u32 request)
{
	struct aa_profile *profile;
	char *buffer, *name;
	int error;
	DEFINE_AUDIT_DATA(sa, LSM_AUDIT_DATA_NONE, op);

	// do we need delegate deleted with mqueues? probably
	//flags |= PATH_DELEGATE_DELETED;

	/* sadly due to rcu walk hairiness, we use dentry_path_raw instead
	 *  of just accessing the name directly, which means we need to
	 *  do the whole buffer allocation mess
	 */
	buffer = aa_get_buffer(false);
	if (!buffer)
		return -ENOMEM;

	error = aa_mqueue_from_path(buffer, path, &name, &sa);
	if (error)
		goto out;

	/* audit fields that won't change during iteration */
	aad(&sa)->request = request;
	aad(&sa)->peer = NULL;
	aad(&sa)->ipc.fsuid = current_fsuid();	/* mqueue uses fsuid() */
	aad(&sa)->ipc.ouid = d_backing_inode(path->dentry) ?
					d_backing_inode(path->dentry)->i_uid:
					current_fsuid();

	error = fn_for_each_confined(label, profile,
			aa_profile_mqueue_perm(profile, request, name,
					       AA_CLASS_POSIX_MQUEUE,
					       &sa));
out:
	aa_put_buffer(buffer);

	return error;
}

int aa_may_mqueue(struct aa_label *label, u32 request, int key)
{
	int ret = 0;
	struct aa_profile *profile;
	char skey[20];
	DEFINE_AUDIT_DATA(sa, LSM_AUDIT_DATA_NONE, "sysv_mqueue");

	if (unconfined(label)) {
		return 0;
	}

	ret = snprintf(skey, 20, "%d", key);
	if (ret >= 20) {
		return -ENAMETOOLONG;
	}

	aad(&sa)->name = skey;
	aad(&sa)->request = request;
	aad(&sa)->peer = NULL;
	aad(&sa)->ipc.fsuid = current_fsuid();
	aad(&sa)->ipc.ouid = current_uid();

	ret = fn_for_each(label, profile,
			  aa_profile_mqueue_perm(profile, request, skey,
						 AA_CLASS_SYSV_MQUEUE,
						 &sa));

	return ret;
}

static void audit_shm_cb(struct audit_buffer *ab, void *va)
{
	struct common_audit_data *sa = va;

	aa_audit_perms(ab, sa, NULL, 0, NULL, AA_AUDIT_SHM_MASK);

	if (aad(sa)->ipc.type == AA_CLASS_POSIX_SHM)
		audit_log_format(ab, " class=\"posix_shm\"");
	else if(aad(sa)->ipc.type == AA_CLASS_SYSV_SHM)
		audit_log_format(ab, " class=\"sysv_shm\"");
	if (aad(sa)->request & AA_AUDIT_FILE_MASK) {
		audit_log_format(ab, " fsuid=%u",
				 from_kuid(&init_user_ns, aad(sa)->ipc.fsuid));
		audit_log_format(ab, " ouid=%u",
				 from_kuid(&init_user_ns, aad(sa)->ipc.ouid));
	}
	if (aad(sa)->peer) {
		audit_log_format(ab, " olabel=");
		aa_label_xaudit(ab, labels_ns(aad(sa)->label), aad(sa)->peer,
				FLAGS_NONE, GFP_ATOMIC);
	}
}

int aa_profile_shm_perm(struct aa_profile *profile, u32 request,
			char *name, int aa_class,
			struct common_audit_data *sa)
{
	struct aa_perms perms = { };
	unsigned int state;

	if (profile_unconfined(profile) ||
	    !PROFILE_MEDIATES(profile, aa_class))
		return 0;

	aad(sa)->label = &profile->label;
	aad(sa)->ipc.type = aa_class;

	state = aa_dfa_match(profile->policy.dfa,
			     profile->policy.start[aa_class],
			     name);
	aa_compute_perms(profile->policy.dfa, state, &perms);
	aa_apply_modes_to_perms(profile, &perms);
	if (!denied_perms(&perms, request)) {
		/* early bailout sufficient perms no need to do further
		 * checks */
		return aa_check_perms(profile, &perms, request, sa,
				      audit_shm_cb);
	}
	/* continue check to see if we have label perms */
	//aa_label_match(profile, peer??, state false, request, &perms);
	//aa_apply_modes_to_perms(profile, &perms);

	// this will just cause failure without above label check
	return aa_check_perms(profile, &perms, request, sa, audit_shm_cb);
}

int aa_may_shm(struct aa_label *label, u32 request, struct kern_ipc_perm *shp)
{
	int ret = 0;
	struct aa_profile *profile;
	char skey[20] = "";
	DEFINE_AUDIT_DATA(sa, LSM_AUDIT_DATA_NONE, "sysv_shm");

	if (unconfined(label)) {
		return 0;
	}

	if (shp) {
		ret = snprintf(skey, 20, "%d", shp->key);
		if (ret >= 20) {
			return -ENAMETOOLONG;
		}
	}

	aad(&sa)->name = skey;
	aad(&sa)->request = request;
	aad(&sa)->peer = NULL;
	aad(&sa)->ipc.fsuid = current_fsuid();
	aad(&sa)->ipc.ouid = current_uid();

	ret = fn_for_each(label, profile,
			  aa_profile_shm_perm(profile, request, skey,
					      AA_CLASS_SYSV_SHM,
					      &sa));

	return ret;
}
