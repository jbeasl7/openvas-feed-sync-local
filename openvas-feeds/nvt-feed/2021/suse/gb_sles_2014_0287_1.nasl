# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2014.0287.1");
  script_cve_id("CVE-2011-1083", "CVE-2011-3593", "CVE-2012-1601", "CVE-2012-2137", "CVE-2012-2372", "CVE-2012-2745", "CVE-2012-3375", "CVE-2012-3412", "CVE-2012-3430", "CVE-2012-3511", "CVE-2012-4444", "CVE-2012-4530", "CVE-2012-4565", "CVE-2012-6537", "CVE-2012-6538", "CVE-2012-6539", "CVE-2012-6540", "CVE-2012-6541", "CVE-2012-6542", "CVE-2012-6544", "CVE-2012-6545", "CVE-2012-6546", "CVE-2012-6547", "CVE-2012-6548", "CVE-2012-6549", "CVE-2013-0160", "CVE-2013-0216", "CVE-2013-0231", "CVE-2013-0268", "CVE-2013-0310", "CVE-2013-0343", "CVE-2013-0349", "CVE-2013-0871", "CVE-2013-0914", "CVE-2013-1767", "CVE-2013-1773", "CVE-2013-1774", "CVE-2013-1792", "CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798", "CVE-2013-1827", "CVE-2013-1928", "CVE-2013-1943", "CVE-2013-2015", "CVE-2013-2141", "CVE-2013-2147", "CVE-2013-2164", "CVE-2013-2232", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2634", "CVE-2013-2851", "CVE-2013-2852", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-2893", "CVE-2013-2897", "CVE-2013-2929", "CVE-2013-3222", "CVE-2013-3223", "CVE-2013-3224", "CVE-2013-3225", "CVE-2013-3228", "CVE-2013-3229", "CVE-2013-3231", "CVE-2013-3232", "CVE-2013-3234", "CVE-2013-3235", "CVE-2013-4345", "CVE-2013-4470", "CVE-2013-4483", "CVE-2013-4511", "CVE-2013-4587", "CVE-2013-4588", "CVE-2013-4591", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6378", "CVE-2013-6383", "CVE-2014-1444", "CVE-2014-1445", "CVE-2014-1446");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:22 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2013-07-16 15:54:00 +0000 (Tue, 16 Jul 2013)");

  script_name("SUSE: Security Advisory (SUSE-SU-2014:0287-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2014:0287-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2014/suse-su-20140287-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux kernel' package(s) announced via the SUSE-SU-2014:0287-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a SUSE Linux Enterprise Server 11 SP1 LTSS roll up update to fix a lot of security issues and non-security bugs.

The following security bugs have been fixed:

 *

 CVE-2011-3593: A certain Red Hat patch to the vlan_hwaccel_do_receive function in net/8021q/vlan_core.c in the Linux kernel 2.6.32 on Red Hat Enterprise Linux
(RHEL) 6 allows remote attackers to cause a denial of service (system crash) via priority-tagged VLAN frames.
(bnc#735347)

 *

 CVE-2012-1601: The KVM implementation in the Linux kernel before 3.3.6 allows host OS users to cause a denial of service (NULL pointer dereference and host OS crash) by making a KVM_CREATE_IRQCHIP ioctl call after a virtual CPU already exists. (bnc#754898)

 *

 CVE-2012-2137: Buffer overflow in virt/kvm/irq_comm.c in the KVM subsystem in the Linux kernel before 3.2.24 allows local users to cause a denial of service (crash) and possibly execute arbitrary code via vectors related to Message Signaled Interrupts (MSI), irq routing entries, and an incorrect check by the setup_routing_entry function before invoking the kvm_set_irq function. (bnc#767612)

 *

 CVE-2012-2372: The rds_ib_xmit function in net/rds/ib_send.c in the Reliable Datagram Sockets (RDS)
protocol implementation in the Linux kernel 3.7.4 and earlier allows local users to cause a denial of service
(BUG_ON and kernel panic) by establishing an RDS connection with the source IP address equal to the IPoIB interfaces own IP address, as demonstrated by rds-ping. (bnc#767610)

 *

 CVE-2012-2745: The copy_creds function in kernel/cred.c in the Linux kernel before 3.3.2 provides an invalid replacement session keyring to a child process,
which allows local users to cause a denial of service
(panic) via a crafted application that uses the fork system call. (bnc#770695)

 *

 CVE-2012-3375: The epoll_ctl system call in fs/eventpoll.c in the Linux kernel before 3.2.24 does not properly handle ELOOP errors in EPOLL_CTL_ADD operations,
which allows local users to cause a denial of service
(file-descriptor consumption and system crash) via a crafted application that attempts to create a circular epoll dependency. NOTE: this vulnerability exists because of an incorrect fix for CVE-2011-1083. (bnc#769896)

 *

 CVE-2012-3412: The sfc (aka Solarflare Solarstorm)
driver in the Linux kernel before 3.2.30 allows remote attackers to cause a denial of service (DMA descriptor consumption and network-controller outage) via crafted TCP packets that trigger a small MSS value. (bnc#774523)

 *

 CVE-2012-3430: The rds_recvmsg function in net/rds/recv.c in the Linux kernel before 3.0.44 does not initialize a certain structure member, which allows local users to obtain potentially sensitive information from kernel stack memory via a (1) recvfrom or (2) recvmsg system call on an RDS socket. (bnc#773383)

 *

 CVE-2012-3511: Multiple race conditions in the madvise_remove function in ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux kernel' package(s) on SUSE Linux Enterprise Server 11-SP1.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"btrfs-kmp-default", rpm:"btrfs-kmp-default~0_2.6.32.59_0.9~0.3.151", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"btrfs-kmp-pae", rpm:"btrfs-kmp-pae~0_2.6.32.59_0.9~0.3.151", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"btrfs-kmp-xen", rpm:"btrfs-kmp-xen~0_2.6.32.59_0.9~0.3.151", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-default", rpm:"ext4dev-kmp-default~0_2.6.32.59_0.9~7.9.118", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-pae", rpm:"ext4dev-kmp-pae~0_2.6.32.59_0.9~7.9.118", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-trace", rpm:"ext4dev-kmp-trace~0_2.6.32.59_0.9~7.9.118", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ext4dev-kmp-xen", rpm:"ext4dev-kmp-xen~0_2.6.32.59_0.9~7.9.118", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hyper-v-kmp-default", rpm:"hyper-v-kmp-default~0_2.6.32.59_0.9~0.18.37", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hyper-v-kmp-pae", rpm:"hyper-v-kmp-pae~0_2.6.32.59_0.9~0.18.37", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hyper-v-kmp-trace", rpm:"hyper-v-kmp-trace~0_2.6.32.59_0.9~0.18.37", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~2.6.32.59~0.9.1", rls:"SLES11.0SP1"))) {
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
