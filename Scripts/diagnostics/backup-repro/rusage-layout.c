/* Local ABI check only. No process attachment or workload. */
#include <sys/resource.h>
#include <stddef.h>
#include <stdio.h>
int main(void) {
    printf("{\"size\":%zu,\"footprintOffset\":%zu,\"lifetimePeakOffset\":%zu,\"intervalPeakOffset\":%zu}\n",
        sizeof(struct rusage_info_v4), offsetof(struct rusage_info_v4, ri_phys_footprint),
        offsetof(struct rusage_info_v4, ri_lifetime_max_phys_footprint),
        offsetof(struct rusage_info_v4, ri_interval_max_phys_footprint));
    return 0;
}
