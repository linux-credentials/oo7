/* Test-only PAM module: supply synthetic tokens without user interaction. */
#include <security/pam_modules.h>

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc,
                                  const char **argv) {
    (void)flags;
    (void)argc;
    (void)argv;
    return pam_set_item(handle, PAM_AUTHTOK, "oo7-test-old-password");
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *handle, int flags, int argc,
                              const char **argv) {
    (void)argc;
    (void)argv;
    if (flags & PAM_PRELIM_CHECK)
        return PAM_SUCCESS;
    int result = pam_set_item(handle, PAM_OLDAUTHTOK, "oo7-test-old-password");
    if (result != PAM_SUCCESS)
        return result;
    return pam_set_item(handle, PAM_AUTHTOK, "oo7-test-new-password");
}
