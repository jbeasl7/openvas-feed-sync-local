# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.1679.1");
  script_cve_id("CVE-2012-1601", "CVE-2012-2372", "CVE-2012-3412", "CVE-2012-3430", "CVE-2012-4461", "CVE-2012-4508", "CVE-2012-5517");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:1679-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:1679-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20121679-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2012:1679-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP2 kernel has been updated to 3.0.51 which fixes various bugs and security issues.

It contains the following feature enhancements:

 * The cachefiles framework is now supported
(FATE#312793, bnc#782369). The userland utilities were published seperately to support this feature.
 * The ipset netfilter modules are now supported
(FATE#313309) The ipset userland utility will be published seperately to support this feature.
 * The tipc kernel module is now externally supported
(FATE#305033).
 * Hyper-V KVP IP injection was implemented
(FATE#314441). A seperate hyper-v package will be published to support this feature.
 * Intel Lynx Point PCH chipset support was added.
(FATE#313409)
 *

 Enable various md/raid10 and DASD enhancements.
(FATE#311379) These make it possible for RAID10 to cope with DASD devices being slow for various reasons - the affected device will be temporarily removed from the array.

 Also added support for reshaping of RAID10 arrays.

 mdadm changes will be published to support this feature.

The following security issues have been fixed:

 * CVE-2012-5517: A race condition on hot adding memory could be used by local attackers to crash the system during hot adding new memory.
 * CVE-2012-4461: A flaw has been found in the way Linux kernels KVM subsystem handled vcpu->arch.cr4 X86_CR4_OSXSAVE bit set upon guest enter. On hosts without the XSAVE feature and using qemu userspace an unprivileged local user could have used this flaw to crash the system.
 * CVE-2012-1601: The KVM implementation in the Linux kernel allowed host OS users to cause a denial of service
(NULL pointer dereference and host OS crash) by making a KVM_CREATE_IRQCHIP ioctl call after a virtual CPU already exists.
 * CVE-2012-2372: Attempting an rds connection from the IP address of an IPoIB interface to itself causes a kernel panic due to a BUG_ON() being triggered. Making the test less strict allows rds-ping to work without crashing the machine. A local unprivileged user could use this flaw to crash the system.
 * CVE-2012-4508: Dimitry Monakhov, one of the ext4 developers, has discovered a race involving asynchronous I/O and fallocate which can lead to the exposure of stale data --- that is, an extent which should have had the
'uninitialized' bit set indicating that its blocks have not yet been written and thus contain data from a deleted file will get exposed to anyone with read access to the file.
 * CVE-2012-3430: The rds_recvmsg function in net/rds/recv.c in the Linux kernel did not initialize a certain structure member, which allows local users to obtain potentially sensitive information from kernel stack memory via a (1) recvfrom or (2) recvmsg system call on an RDS socket.
 * CVE-2012-3412: The sfc (aka Solarflare Solarstorm)
driver in the Linux kernel allowed remote attackers to cause a denial of service (DMA descriptor consumption and ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux kernel' package(s) on SUSE Linux Enterprise Desktop 11-SP2, SUSE Linux Enterprise High Availability Extension 11-SP2, SUSE Linux Enterprise Server 11-SP2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES11.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-base", rpm:"kernel-ppc64-base~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-devel", rpm:"kernel-ppc64-devel~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.51~0.7.9.1", rls:"SLES11.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
