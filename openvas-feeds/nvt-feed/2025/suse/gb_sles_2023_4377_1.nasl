# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4377.1");
  script_cve_id("CVE-2023-2163", "CVE-2023-31085", "CVE-2023-3111", "CVE-2023-34324", "CVE-2023-39189", "CVE-2023-39192", "CVE-2023-39193", "CVE-2023-39194", "CVE-2023-42754", "CVE-2023-45862");
  script_tag(name:"creation_date", value:"2025-02-17 04:07:12 +0000 (Mon, 17 Feb 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-22 02:02:18 +0000 (Fri, 22 Sep 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4377-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4377-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234377-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210778");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1210853");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215518");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215858");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215860");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215861");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216046");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1216134");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-November/017001.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2023:4377-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP2 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2023-31085: Fixed a divide-by-zero error in do_div(sz,mtd->erasesize) that could cause a local DoS. (bsc#1210778)
- CVE-2023-45862: Fixed an issue in the ENE UB6250 reader driver whwere an object could potentially extend beyond the end of an allocation causing. (bsc#1216051)
- CVE-2023-2163: Fixed an incorrect verifier pruning in BPF that could lead to unsafe code paths being incorrectly marked as safe, resulting in arbitrary read/write in kernel memory, lateral privilege escalation, and container escape. (bsc#1215518)
- CVE-2023-34324: Fixed a possible deadlock in Linux kernel event handling. (bsc#1215745).
- CVE-2023-39189: Fixed a flaw in the Netfilter subsystem that could allow a local privileged (CAP_NET_ADMIN) attacker to trigger an out-of-bounds read, leading to a crash or information disclosure. (bsc#1216046)
- CVE-2023-3111: Fixed a use-after-free vulnerability in prepare_to_relocate in fs/btrfs/relocation.c (bsc#1212051).
- CVE-2023-39194: Fixed an out of bounds read in the XFRM subsystem (bsc#1215861).
- CVE-2023-39193: Fixed an out of bounds read in the xtables subsystem (bsc#1215860).
- CVE-2023-39192: Fixed an out of bounds read in the netfilter (bsc#1215858).
- CVE-2023-42754: Fixed a NULL pointer dereference in the IPv4 stack that could lead to denial of service (bsc#1215467).

The following non-security bugs were fixed:

- KVM: x86: fix sending PV IPI (git-fixes, bsc#1210853, bsc#1216134).
- bpf: propagate precision in ALU/ALU64 operations (git-fixes).");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~5.3.18~150200.24.169.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~5.3.18~150200.24.169.1.150200.9.85.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~5.3.18~150200.24.169.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~5.3.18~150200.24.169.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-docs", rpm:"kernel-docs~5.3.18~150200.24.169.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~5.3.18~150200.24.169.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-obs-build", rpm:"kernel-obs-build~5.3.18~150200.24.169.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt", rpm:"kernel-preempt~5.3.18~150200.24.169.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-preempt-devel", rpm:"kernel-preempt-devel~5.3.18~150200.24.169.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~5.3.18~150200.24.169.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~5.3.18~150200.24.169.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"reiserfs-kmp-default", rpm:"reiserfs-kmp-default~5.3.18~150200.24.169.1", rls:"SLES15.0SP2"))) {
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
