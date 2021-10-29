#include "include/module.h"
#include "include/audit.h"
#include <linux/printk.h>

/**
 * audit_cb - call back for module components of audit struct
 * @ab - audit buffer   (NOT NULL)
 * @va - audit struct to audit data from  (NOT NULL)
 */
static void audit_cb(struct audit_buffer *ab, void *va)
{
	struct common_audit_data *sa = va;

	audit_log_format(ab, " module_data");
}


int aa_module_data(struct aa_profile *profile)
{
	DEFINE_AUDIT_DATA(sa, LSM_AUDIT_DATA_MODULE, OP_MODULE_DATA);
	
	printk(KERN_ERR "aa_module_data name: %s hname: %s\n", profile->base.name , profile->base.hname);
	printk(KERN_ERR "aa_module_data mod.allow %d, mod.audit %d, mod.quiet %d\n", profile->mod.allow , profile->mod.audit, profile->mod.quiet);
	
	if (profile_unconfined(profile))
		goto dont_mediate;
	if (!PROFILE_MEDIATES(profile, AA_CLASS_MODULE))
		goto dont_mediate;

	if (profile->mod.allow)
		return 0;
	else
		return -EPERM;
//	printk(KERN_ERR "aa_module_data checkperms %d\n", checkperms);
dont_mediate:
	printk(KERN_ERR "aa_module_data dont mediate\n");
	return 0;
	
}
