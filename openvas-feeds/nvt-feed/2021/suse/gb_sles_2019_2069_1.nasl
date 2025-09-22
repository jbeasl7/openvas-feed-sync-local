# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2069.1");
  script_cve_id("CVE-2018-16871", "CVE-2018-20836", "CVE-2018-20855", "CVE-2019-10638", "CVE-2019-10639", "CVE-2019-1125", "CVE-2019-11478", "CVE-2019-11599", "CVE-2019-11810", "CVE-2019-12614", "CVE-2019-12817", "CVE-2019-12818", "CVE-2019-12819", "CVE-2019-13233", "CVE-2019-13631", "CVE-2019-13648", "CVE-2019-14283", "CVE-2019-14284");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:20 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-07 18:59:15 +0000 (Tue, 07 May 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2069-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2069-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192069-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel for Azure' package(s) announced via the SUSE-SU-2019:2069-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP1 Azure kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:
CVE-2018-20855: An issue was discovered in create_qp_common,
 mlx5_ib_create_qp_resp was never initialized, resulting in a leak of
 stack memory to userspace. (bnc#bsc#1103991)

CVE-2019-1125: Fix Spectre V1 variant via swapgs: Exclude ATOMs from
 speculation through SWAPGS (bsc#1139358).

CVE-2019-14284: In the Linux kernel, drivers/block/floppy.c allowed a
 denial of service by setup_format_params division-by-zero.
 (bnc#bsc#1143189)

CVE-2019-14283: In the Linux kernel, set_geometry in
 drivers/block/floppy.c did not validate the sect and head fields, as
 demonstrated by an integer overflow and out-of-bounds read. It can be
 triggered by an unprivileged local user when a floppy disk has been
 inserted. NOTE: QEMU creates the floppy device by default. (bsc#1143191)

CVE-2019-11810: An issue was discovered in the Linux kernel A NULL
 pointer dereference can occur when megasas_create_frame_pool() fails in
 megasas_alloc_cmds() in drivers/scsi/megaraid/megaraid_sas_base.c. This
 causes a Denial of Service, related to a use-after-free. (bsc#1134399)

CVE-2019-13648: In the Linux kernel on the powerpc platform, when
 hardware transactional memory was disabled, a local user can cause a
 denial of service via a sigreturn() system call that sends a crafted
 signal frame. (bnc#1142265)

CVE-2019-13631: In parse_hid_report_descriptor, a malicious usb device
 could send an hid: report that triggered an out-of-bounds write during
 generation of debugging messages. (bnc#1142023)

CVE-2019-10638: In the Linux kernel, a device could be tracked by an
 attacker using the IP ID values the kernel produces for connection-less
 protocols (e.g., UDP and ICMP). When such traffic was sent to multiple
 destination IP addresses, it was possible to obtain hash collisions (of
 indices to the counter array) and thereby obtain the hashing key (via
 enumeration). An attack may have been conducted by hosting a crafted web
 page that uses WebRTC or gQUIC to force UDP traffic to
 attacker-controlled IP addresses. (bnc#1140575)

CVE-2019-10639: The Linux kernel allowed Information Exposure (partial
 kernel address disclosure), leading to a KASLR bypass. (bsc#1140577)

CVE-2019-13233: In arch/x86/lib/insn-eval.c, there was a use-after-free
 for access to an LDT entry because of a race condition between
 modify_ldt() and a #BR exception for an MPX bounds violation.
 (bnc#1140454)

CVE-2018-20836: In the Linux kernel there was a race condition in
 smp_task_timedout() and smp_task_done() in
 drivers/scsi/libsas/sas_expander.c, leading to a use-after-free.
 (bnc#1134395)

CVE-2019-11599: The coredump implementation in the Linux kernel did not
 use locking or other mechanisms to prevent vma layout or vma flags
 changes while it runs, which allowed local users to obtain ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel for Azure' package(s) on SUSE Linux Enterprise Module for Public Cloud 15-SP1.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure", rpm:"kernel-azure~4.12.14~8.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base", rpm:"kernel-azure-base~4.12.14~8.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-base-debuginfo", rpm:"kernel-azure-base-debuginfo~4.12.14~8.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-debuginfo", rpm:"kernel-azure-debuginfo~4.12.14~8.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-azure-devel", rpm:"kernel-azure-devel~4.12.14~8.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel-azure", rpm:"kernel-devel-azure~4.12.14~8.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source-azure", rpm:"kernel-source-azure~4.12.14~8.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms-azure", rpm:"kernel-syms-azure~4.12.14~8.13.1", rls:"SLES15.0SP1"))) {
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
