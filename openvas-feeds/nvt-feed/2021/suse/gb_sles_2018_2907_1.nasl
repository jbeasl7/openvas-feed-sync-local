# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.2907.1");
  script_cve_id("CVE-2018-10902", "CVE-2018-10940", "CVE-2018-14634", "CVE-2018-14734", "CVE-2018-15572", "CVE-2018-16658", "CVE-2018-6554", "CVE-2018-6555");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:36 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-25 13:53:37 +0000 (Thu, 25 Oct 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:2907-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0|SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:2907-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20182907-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1057199");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1087081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1092903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1102517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1103119");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104684");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1104818");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105100");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105322");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105323");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1105536");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106509");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1106511");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107001");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1107689");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1108912");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2018-September/004617.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2018:2907-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 11 SP3 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2018-14634: Prevent integer overflow in create_elf_tables that allowed a
 local attacker to exploit this vulnerability via a SUID-root binary and obtain
 full root privileges (bsc#1108912).
- CVE-2018-10940: The cdrom_ioctl_media_changed function allowed local
 attackers to use a incorrect bounds check in the CDROM driver
 CDROM_MEDIA_CHANGED ioctl to read out kernel memory (bsc#1092903)
- CVE-2018-16658: Prevent information leak in cdrom_ioctl_drive_status that
 could have been used by local attackers to read kernel memory (bnc#1107689)
- CVE-2018-6555: The irda_setsockopt function allowed local users to cause a
 denial of service (ias_object use-after-free and system crash) or possibly have
 unspecified other impact via an AF_IRDA socket (bnc#1106511)
- CVE-2018-6554: Prevent memory leak in the irda_bind function that allowed
 local users to cause a denial of service (memory consumption) by repeatedly
 binding an AF_IRDA socket (bnc#1106509)
- CVE-2018-15572: The spectre_v2_select_mitigation function did not always fill
 RSB upon a context switch, which made it easier for attackers to conduct
 userspace-userspace spectreRSB attacks (bnc#1102517)
- CVE-2018-10902: Protect against concurrent access to prevent double realloc
 (double free) in snd_rawmidi_input_params() and snd_rawmidi_output_status(). A
 malicious local attacker could have used this for privilege escalation
 (bnc#1105322).
- CVE-2018-14734: ucma_leave_multicast accessed a certain data structure after
 a cleanup step in ucma_process_join, which allowed attackers to cause a denial
 of service (use-after-free) (bsc#1103119).

The following non-security bugs were fixed:

- KVM: VMX: Work around kABI breakage in 'enum vmx_l1d_flush_state' (bsc#1106369).
- KVM: VMX: fixes for vmentry_l1d_flush module parameter (bsc#1106369).
- KVM: x86: Free vmx_msr_bitmap_longmode while kvm_init failed (bsc#1104367).
- Refresh patches.xen/xen3-x86-l1tf-04-protect-PROT_NONE-ptes.patch (bsc#1105100).
- kabi: x86/speculation/l1tf: Increase l1tf memory limit for Nehalem+ (bnc#1105536).
- kabi: x86/speculation/l1tf: Increase l1tf memory limit for Nehalem+ (bnc#1105536).
- ptrace: fix PTRACE_LISTEN race corrupting task->state (bnc#1107001).
- rpm/kernel-docs.spec.in: Expand kernel tree directly from sources (bsc#1057199)
- x86, l1tf: Protect PROT_NONE PTEs against speculation fixup (bnc#1104684, bnc#1104818).
- x86/speculation/l1tf: Fix off-by-one error when warning that system has too much RAM (bnc#1105536).
- x86/speculation/l1tf: Fix overflow in l1tf_pfn_limit() on 32bit (bnc#1087081).
- x86/speculation/l1tf: Increase l1tf memory limit for Nehalem+ (bnc#1105536).
- x86/speculation/l1tf: Suggest what to do on systems with too much RAM (bnc#1105536).
- xen x86/speculation/l1tf: Fix off-by-one ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-extra", rpm:"kernel-bigsmp-extra~3.0.101~0.47.106.50.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-extra", rpm:"kernel-default-extra~3.0.101~0.47.106.50.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-extra", rpm:"kernel-pae-extra~3.0.101~0.47.106.50.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ppc64-extra", rpm:"kernel-ppc64-extra~3.0.101~0.47.106.50.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-extra", rpm:"kernel-trace-extra~3.0.101~0.47.106.50.1", rls:"SLES11.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-extra", rpm:"kernel-xen-extra~3.0.101~0.47.106.50.1", rls:"SLES11.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp", rpm:"kernel-bigsmp~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-base", rpm:"kernel-bigsmp-base~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-bigsmp-devel", rpm:"kernel-bigsmp-devel~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2", rpm:"kernel-ec2~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-base", rpm:"kernel-ec2-base~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-ec2-devel", rpm:"kernel-ec2-devel~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae", rpm:"kernel-pae~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-base", rpm:"kernel-pae-base~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-pae-devel", rpm:"kernel-pae-devel~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace", rpm:"kernel-trace~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-base", rpm:"kernel-trace-base~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-trace-devel", rpm:"kernel-trace-devel~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen", rpm:"kernel-xen~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-base", rpm:"kernel-xen-base~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-xen-devel", rpm:"kernel-xen-devel~3.0.101~0.47.106.50.1", rls:"SLES11.0SP3"))) {
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
