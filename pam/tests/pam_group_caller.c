/* Exercise only synthetic PAM credentials; keep the caller alive for delivery. */
#include <grp.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <unistd.h>

static int no_conversation(int count, const struct pam_message **messages,
                           struct pam_response **responses, void *data) {
    (void)count;
    (void)messages;
    (void)responses;
    (void)data;
    return PAM_CONV_ERR;
}

static int original_credentials(void) {
    gid_t group = (gid_t)-1;
    return getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0 &&
           getgroups(1, &group) == 1 && group == 0;
}

int main(int argc, char **argv) {
    gid_t group = 0;
    if (argc != 3 || setgroups(1, &group) != 0 || !original_credentials())
        return 1;

    struct pam_conv conversation = {no_conversation, NULL};
    pam_handle_t *handle = NULL;
    int result = pam_start_confdir("oo7-test", argv[2], &conversation,
                                   argv[1], &handle);
    if (result != PAM_SUCCESS)
        return result;
    result = pam_authenticate(handle, 0);
    if (result == PAM_SUCCESS)
        result = pam_open_session(handle, 0);

    /* The group assertion must not depend on detached-sender lifetime fixes. */
    if (result == PAM_SUCCESS && getchar() != '\n')
        result = PAM_SYSTEM_ERR;
    if (!original_credentials())
        result = PAM_SYSTEM_ERR;
    /* End this process without testing PAM teardown of a detached sender. */
    return result;
}
