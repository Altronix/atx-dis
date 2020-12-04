#include "atx-dis.h"

int main(int argc, const char *const *argv)
{
	getHOSTNAME(HOSTNAME, sizeof(HOSTNAME));

	SvcConfig cfg = {
			.service = ATX_SERVICE,
			.hostname = HOSTNAME,
			.port = ATX_PORT_SERVICE};

	runService(cfg);

	return 0;
}
