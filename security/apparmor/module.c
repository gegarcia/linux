#include <module.h>

int aa_module_data(struct aa_profile *profile)
{
	unsigned long state;

	if (profile_unconfined(profile))
		return 0;
	state = PROFILE_MEDIATES(profile, AA_CLASS_MODULE);
	if (!state)
		return 0;

	state = aa_dfa_match(profile->policy.dfa, state,);
	
	
	
}
