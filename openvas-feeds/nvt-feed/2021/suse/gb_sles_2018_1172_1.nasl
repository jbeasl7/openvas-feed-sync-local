# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.1172.1");
  script_cve_id("CVE-2015-5156", "CVE-2016-7915", "CVE-2017-0861", "CVE-2017-12190", "CVE-2017-13166", "CVE-2017-16644", "CVE-2017-16911", "CVE-2017-16912", "CVE-2017-16913", "CVE-2017-16914", "CVE-2017-18203", "CVE-2017-18208", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-1087", "CVE-2018-6927", "CVE-2018-7566", "CVE-2018-7757", "CVE-2018-8822", "CVE-2018-8897");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:45 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-20 14:00:15 +0000 (Wed, 20 Jun 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:1172-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:1172-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20181172-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1010470");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1039348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1052943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062568");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1062840");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1063416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1067118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1072865");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078669");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078672");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1078674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080464");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1080757");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1082424");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083242");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083483");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1083494");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1084536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1085331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1086162");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087088");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087209");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088147");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1088260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089608");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1089752");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/940776");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-May/003978.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:1172-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP3 LTSS kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-1087: And an unprivileged KVM guest user could use this flaw to potentially escalate their privileges inside a guest. (bsc#1087088)
- CVE-2018-8897: An unprivileged system user could use incorrect set up interrupt stacks to crash the Linux kernel resulting in DoS issue. (bsc#1087088)
- CVE-2018-10124: The kill_something_info function in kernel/signal.c might allow local users to cause a denial of service via an INT_MIN argument (bnc#1089752).
- CVE-2018-10087: The kernel_wait4 function in kernel/exit.c might allow local users to cause a denial of service by triggering an attempted use of the -INT_MIN value (bnc#1089608).
- CVE-2018-7757: Memory leak in the sas_smp_get_phy_events function in drivers/scsi/libsas/sas_expander.c allowed local users to cause a denial of service (memory consumption) via many read accesses to files in the /sys/class/sas_phy directory, as demonstrated by the /sys/class/sas_phy/phy-1:0:12/invalid_dword_count file (bnc#1084536 1087209).
- CVE-2018-7566: A Buffer Overflow via an SNDRV_SEQ_IOCTL_SET_CLIENT_POOL ioctl write operation to /dev/snd/seq by a local user was fixed (bnc#1083483).
- CVE-2017-0861: Use-after-free vulnerability in the snd_pcm_info function in the ALSA subsystem allowed attackers to gain privileges via unspecified vectors (bnc#1088260).
- CVE-2018-8822: Incorrect buffer length handling in the ncp_read_kernel function in fs/ncpfs/ncplib_kernel.c could be exploited by malicious NCPFS servers to crash the kernel or execute code (bnc#1086162).
- CVE-2017-13166: An elevation of privilege vulnerability in the kernel v4l2 video driver. (bnc#1072865).
- CVE-2017-18203: The dm_get_from_kobject function in drivers/md/dm.c allow local users to cause a denial of service (BUG) by leveraging a race condition with __dm_destroy during creation and removal of DM devices (bnc#1083242).
- CVE-2017-16911: The vhci_hcd driver allowed allows local attackers to disclose kernel memory addresses. Successful exploitation requires that a USB device is attached over IP (bnc#1078674).
- CVE-2017-18208: The madvise_willneed function in mm/madvise.c allowed local users to cause a denial of service (infinite loop) by triggering use of MADVISE_WILLNEED for a DAX mapping (bnc#1083494).
- CVE-2017-16644: The hdpvr_probe function in drivers/media/usb/hdpvr/hdpvr-core.c allowed local users to cause a denial of service (improper error handling and system crash) or possibly have unspecified other impact via a crafted USB device (bnc#1067118).
- CVE-2018-6927: The futex_requeue function in kernel/futex.c might allow attackers to cause a denial of service (integer overflow) or possibly have unspecified other impact by triggering a negative wake or requeue value (bnc#1080757).
- CVE-2017-16914: The ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-extra", rpm:"kernel-bigsmp-extra~3.0.101~0.47.106.22.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~0.47.106.22.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~0.47.106.22.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~0.47.106.22.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~0.47.106.22.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~0.47.106.22.1", rls:"SLES11.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-base", rpm:"kernel-bigsmp-base~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-devel", rpm:"kernel-bigsmp-devel~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.47.106.22.1", rls:"SLES11.0SP3"))) {
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
