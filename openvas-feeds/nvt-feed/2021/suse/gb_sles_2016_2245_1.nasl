# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2245.1");
  script_cve_id("CVE-2013-4312", "CVE-2015-7513", "CVE-2015-7833", "CVE-2016-0758", "CVE-2016-1583", "CVE-2016-2053", "CVE-2016-2187", "CVE-2016-3134", "CVE-2016-3955", "CVE-2016-4470", "CVE-2016-4482", "CVE-2016-4485", "CVE-2016-4486", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4805", "CVE-2016-4913", "CVE-2016-4997", "CVE-2016-4998", "CVE-2016-5244", "CVE-2016-5696", "CVE-2016-5829", "CVE-2016-6480");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:04 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-07-05 17:21:17 +0000 (Tue, 05 Jul 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2245-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2245-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162245-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/839104");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/866130");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919351");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/944309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/950998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/960689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/962404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/963762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/966460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/969149");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/970114");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971446");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971729");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/971944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/974428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/975945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/978822");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979274");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979548");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979681");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/979879");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980788");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/980931");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/981267");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983143");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/983535");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/984755");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986362");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986572");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/987709");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/988065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989152");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/989401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/991608");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-September/002255.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2016:2245-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP3 LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
- CVE-2016-3955: The usbip_recv_xbuff function in drivers/usb/usbip/usbip_common.c in the Linux kernel allowed remote attackers to cause a denial of service (out-of-bounds write) or possibly have unspecified other impact via a crafted length value in a USB/IP packet (bnc#975945).
- CVE-2016-4998: The IPT_SO_SET_REPLACE setsockopt implementation in the netfilter subsystem in the Linux kernel allowed local users to cause a denial of service (out-of-bounds read) or possibly obtain sensitive information from kernel heap memory by leveraging in-container root access to provide a crafted offset value that leads to crossing a ruleset blob boundary (bnc#986365).
- CVE-2015-7513: arch/x86/kvm/x86.c in the Linux kernel did not reset the PIT counter values during state restoration, which allowed guest OS users to cause a denial of service (divide-by-zero error and host OS crash) via a zero value, related to the kvm_vm_ioctl_set_pit and kvm_vm_ioctl_set_pit2 functions (bnc#960689).
- CVE-2013-4312: The Linux kernel allowed local users to bypass file-descriptor limits and cause a denial of service (memory consumption) by sending each descriptor over a UNIX socket before closing it, related to net/unix/af_unix.c and net/unix/garbage.c (bnc#839104).
- CVE-2016-4997: The compat IPT_SO_SET_REPLACE setsockopt implementation in the netfilter subsystem in the Linux kernel allowed local users to gain privileges or cause a denial of service (memory corruption) by leveraging in-container root access to provide a crafted offset value that triggers an unintended decrement (bnc#986362).
- CVE-2016-5829: Multiple heap-based buffer overflows in the hiddev_ioctl_usage function in drivers/hid/usbhid/hiddev.c in the Linux kernel allow local users to cause a denial of service or possibly have unspecified other impact via a crafted (1) HIDIOCGUSAGES or (2) HIDIOCSUSAGES ioctl call (bnc#986572).
- CVE-2016-4470: The key_reject_and_link function in security/keys/key.c in the Linux kernel did not ensure that a certain data structure was initialized, which allowed local users to cause a denial of service (system crash) via vectors involving a crafted keyctl request2 command (bnc#984755).
- CVE-2016-5244: The rds_inc_info_copy function in net/rds/recv.c in the Linux kernel did not initialize a certain structure member, which allowed remote attackers to obtain sensitive information from kernel stack memory by reading an RDS message (bnc#983213).
- CVE-2016-1583: The ecryptfs_privileged_open function in fs/ecryptfs/kthread.c in the Linux kernel allowed local users to gain privileges or cause a denial of service (stack memory consumption) via vectors involving crafted mmap calls for /proc pathnames, leading to recursive pagefault handling (bnc#983143).
- CVE-2016-4913: The ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 11-SP3.");

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

if(release == "SLES11.0") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-extra", rpm:"kernel-bigsmp-extra~3.0.101~0.47.86.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~0.47.86.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~0.47.86.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~0.47.86.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~0.47.86.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~0.47.86.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-base", rpm:"kernel-bigsmp-base~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-devel", rpm:"kernel-bigsmp-devel~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.47.86.1", rls:"SLES11.0SP3"))) {
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
