# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.2517.1");
  script_cve_id("CVE-2019-9893");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:16 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-26 14:00:18 +0000 (Tue, 26 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:2517-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:2517-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20192517-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libseccomp' package(s) announced via the SUSE-SU-2019:2517-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libseccomp fixes the following issues:

Security issues fixed:
CVE-2019-9893: An incorrect generation of syscall filters in libseccomp
 was fixed (bsc#1128828)

libseccomp was updated to new upstream release 2.4.1:
Fix a BPF generation bug where the optimizer mistakenly identified
 duplicate BPF code blocks.

libseccomp was updated to 2.4.0 (bsc#1128828 CVE-2019-9893):
Update the syscall table for Linux v5.0-rc5

Added support for the SCMP_ACT_KILL_PROCESS action

Added support for the SCMP_ACT_LOG action and SCMP_FLTATR_CTL_LOG
 attribute

Added explicit 32-bit (SCMP_AX_32(...)) and 64-bit (SCMP_AX_64(...))
 argument comparison macros to help protect against unexpected sign
 extension

Added support for the parisc and parisc64 architectures

Added the ability to query and set the libseccomp API level via
 seccomp_api_get(3) and seccomp_api_set(3)

Return -EDOM on an endian mismatch when adding an architecture to a
 filter

Renumber the pseudo syscall number for subpage_prot() so it no longer
 conflicts with spu_run()

Fix PFC generation when a syscall is prioritized, but no rule exists

Numerous fixes to the seccomp-bpf filter generation code

Switch our internal hashing function to jhash/Lookup3 to MurmurHash3

Numerous tests added to the included test suite, coverage now at ~92%

Update our Travis CI configuration to use Ubuntu 16.04

Numerous documentation fixes and updates

libseccomp was updated to release 2.3.3:
Updated the syscall table for Linux v4.15-rc7");

  script_tag(name:"affected", value:"'libseccomp' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libseccomp-debugsource", rpm:"libseccomp-debugsource~2.4.1~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp-devel", rpm:"libseccomp-devel~2.4.1~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2", rpm:"libseccomp2~2.4.1~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2-32bit", rpm:"libseccomp2-32bit~2.4.1~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2-32bit-debuginfo", rpm:"libseccomp2-32bit-debuginfo~2.4.1~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2-debuginfo", rpm:"libseccomp2-debuginfo~2.4.1~3.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libseccomp-debugsource", rpm:"libseccomp-debugsource~2.4.1~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp-devel", rpm:"libseccomp-devel~2.4.1~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2", rpm:"libseccomp2~2.4.1~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2-32bit", rpm:"libseccomp2-32bit~2.4.1~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2-32bit-debuginfo", rpm:"libseccomp2-32bit-debuginfo~2.4.1~3.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libseccomp2-debuginfo", rpm:"libseccomp2-debuginfo~2.4.1~3.3.1", rls:"SLES15.0SP1"))) {
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
