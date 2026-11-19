#ifndef __CCA_TPM_RELAY_H__
#define __CCA_TPM_RELAY_H__

#define SOCKET_PATH         "/tmp/cca-tpm.sock"
#define CTL_SOCKET_PATH     "/tmp/cca-ctl.sock"
#define TPM_BUFSIZE         4096
#define TPM_HDR_SIZE		10	/* tag(2) size(4) code(4) */
#define TPM_RC_FAILURE		0x101
#define RESPONSE_TIMEOUT_MS	120000

#endif /*__CCA_TPM_RELAY_H__*/
