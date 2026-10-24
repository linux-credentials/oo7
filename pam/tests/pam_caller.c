/* A short-lived Linux-PAM application; never authenticates a real password. */
#include <pwd.h>
#include <security/pam_appl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int no_conversation(int count, const struct pam_message **messages,
                           struct pam_response **responses, void *data) {
    (void)count;
    (void)messages;
    (void)responses;
    (void)data;
    return PAM_CONV_ERR;
}

int main(int argc, char **argv) {
    if (argc != 3)
        return 1;

    struct passwd *user = getpwuid(getuid());
    if (!user || user->pw_gid != getgid())
        return 1;

    struct pam_conv conversation = {no_conversation, NULL};
    pam_handle_t *handle = NULL;
    int result = pam_start_confdir("oo7-test", user->pw_name, &conversation,
                                   argv[1], &handle);
    if (result != PAM_SUCCESS)
        return result;

    int session = strcmp(argv[2], "session") == 0;
    if (session) {
        result = pam_authenticate(handle, 0);
        if (result != PAM_SUCCESS) {
            pam_end(handle, result);
            return result;
        }
    }

    setvbuf(stdout, NULL, _IONBF, 0);
    puts("calling");
    result = session ? pam_open_session(handle, 0) : pam_chauthtok(handle, 0);
    printf("returned %d\n", result);
    if (session && result == PAM_SUCCESS)
        pam_close_session(handle, 0);
    pam_end(handle, result);
    return result;
}
