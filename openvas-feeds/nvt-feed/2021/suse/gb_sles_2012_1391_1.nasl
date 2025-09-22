# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2012.1391.1");
  script_cve_id("CVE-2010-4649", "CVE-2011-1044", "CVE-2011-2494", "CVE-2011-4110", "CVE-2012-2136", "CVE-2012-2663", "CVE-2012-2744", "CVE-2012-3400", "CVE-2012-3510");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:26 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2012:1391-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES10\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2012:1391-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2012/suse-su-20121391-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2012:1391-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This Linux kernel update fixes various security issues and bugs in the SUSE Linux Enterprise 10 SP4 kernel.

The following security issues have been fixed:

 *

 CVE-2011-2494: kernel/taskstats.c in the Linux kernel allowed local users to obtain sensitive I/O statistics by sending taskstats commands to a netlink socket, as demonstrated by discovering the length of another users password (a side channel attack).

 *

 CVE-2012-2744:
net/ipv6/netfilter/nf_conntrack_reasm.c in the Linux kernel, when the nf_conntrack_ipv6 module is enabled,
allowed remote attackers to cause a denial of service (NULL pointer dereference and system crash) via certain types of fragmented IPv6 packets.

 *

 CVE-2012-3510: Use-after-free vulnerability in the xacct_add_tsk function in kernel/tsacct.c in the Linux kernel allowed local users to obtain potentially sensitive information from kernel memory or cause a denial of service
(system crash) via a taskstats TASKSTATS_CMD_ATTR_PID command.

 *

 CVE-2011-4110: The user_update function in security/keys/user_defined.c in the Linux kernel 2.6 allowed local users to cause a denial of service (NULL pointer dereference and kernel oops) via vectors related to a user-defined key and updating a negative key into a fully instantiated key.

 *

 CVE-2011-1044: The ib_uverbs_poll_cq function in drivers/infiniband/core/uverbs_cmd.c in the Linux kernel did not initialize a certain response buffer, which allowed local users to obtain potentially sensitive information from kernel memory via vectors that cause this buffer to be only partially filled, a different vulnerability than CVE-2010-4649.

 *

 CVE-2012-3400: Heap-based buffer overflow in the udf_load_logicalvol function in fs/udf/super.c in the Linux kernel allowed remote attackers to cause a denial of service (system crash) or possibly have unspecified other impact via a crafted UDF filesystem.

 *

 CVE-2012-2136: The sock_alloc_send_pskb function in net/core/sock.c in the Linux kernel did not properly validate a certain length value, which allowed local users to cause a denial of service (heap-based buffer overflow and system crash) or possibly gain privileges by leveraging access to a TUN/TAP device.

 *

 CVE-2012-2663: A small denial of service leak in dropping syn+fin messages was fixed.

The following non-security issues have been fixed:

Packaging:

 * kbuild: Fix gcc -x syntax (bnc#773831).

NFS:

 * knfsd: An assortment of little fixes to the sunrpc cache code (bnc#767766).
 * knfsd: Unexport cache_fresh and fix a small race
(bnc#767766).
 * knfsd: nfsd: do not drop silently on upcall deferral
(bnc#767766).
 * knfsd: svcrpc: remove another silent drop from deferral code (bnc#767766).
 * sunrpc/cache: simplify cache_fresh_locked and cache_fresh_unlocked (bnc#767766).
 * sunrpc/cache: recheck cache validity after cache_defer_req (bnc#767766).
 * sunrpc/cache: use list_del_init for the list_head ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux kernel' package(s) on SUSE Linux Enterprise Desktop 10-SP4, SUSE Linux Enterprise Server 10-SP4.");

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

if(release == "SLES10.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~2.6.16.60~0.99.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-debug", rpm:"kernel-debug~2.6.16.60~0.99.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.16.60~0.99.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-iseries64", rpm:"kernel-iseries64~2.6.16.60~0.99.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdump", rpm:"kernel-kdump~2.6.16.60~0.99.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-kdumppae", rpm:"kernel-kdumppae~2.6.16.60~0.99.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64", rpm:"kernel-ppc64~2.6.16.60~0.99.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-smp", rpm:"kernel-smp~2.6.16.60~0.99.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.16.60~0.99.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.16.60~0.99.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmi", rpm:"kernel-vmi~2.6.16.60~0.99.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-vmipae", rpm:"kernel-vmipae~2.6.16.60~0.99.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.16.60~0.99.1", rls:"SLES10.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xenpae", rpm:"kernel-xenpae~2.6.16.60~0.99.1", rls:"SLES10.0SP4"))) {
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
