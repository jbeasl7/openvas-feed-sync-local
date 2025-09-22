# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.0736.1");
  script_cve_id("CVE-2020-29368", "CVE-2020-29374", "CVE-2021-26930", "CVE-2021-26931", "CVE-2021-26932");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-23 18:35:29 +0000 (Tue, 23 Feb 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:0736-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:0736-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20210736-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1065600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1163592");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176831");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178762");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179045");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179082");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179428");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179660");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1180906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181753");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1181843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182140");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182175");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-March/008454.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Linux Kernel' package(s) announced via the SUSE-SU-2021:0736-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 12 SP4 kernel was updated to receive various security and bugfixes.

The following security bugs were fixed:

- CVE-2021-26930: Fixed an improper error handling in blkback's grant mapping (XSA-365 bsc#1181843).
- CVE-2021-26931: Fixed an issue where Linux kernel was treating grant mapping errors as bugs (XSA-362 bsc#1181753).
- CVE-2021-26932: Fixed improper error handling issues in Linux grant mapping (XSA-361 bsc#1181747).
 by remote attackers to read or write files via directory traversal in an XCOPY request (bsc#178372).
- CVE-2020-29368,CVE-2020-29374: Fixed an issue in copy-on-write implementation which could have granted unintended write access
 because of a race condition in a THP mapcount check (bsc#1179660, bsc#1179428).

The following non-security bugs were fixed:

- cifs: check all path components in resolved dfs target (bsc#1180906).
- cifs: fix check of tcon dfs in smb1 (bsc#1180906).
- cifs: fix nodfs mount option (bsc#1180906).
- cifs: introduce helper for finding referral server (bsc#1180906).
- kernel-{binary,source}.spec.in: do not create loop symlinks (bsc#1179082)
- kernel-binary.spec: Add back initrd and image symlink ghosts to filelist (bsc#1182140). Fixes: 76a9256314c3 ('rpm/kernel-{source,binary}.spec: do not include ghost symlinks (boo#1179082).')
- kernel-source.spec: Fix build with rpm 4.16 (boo#1179015). RPM_BUILD_ROOT is cleared before %%install. Do the unpack into RPM_BUILD_ROOT in %%install
- rpm/kernel-binary.spec.in: avoid using barewords (bsc#1179014)
- rpm/kernel-binary.spec.in: avoid using more barewords (bsc#1179014) %split_extra still contained two.
- rpm/kernel-binary.spec.in: Fix compressed module handling for in-tree KMP (jsc#SLE-10886)
- rpm/kernel-binary.spec.in: use grep -E instead of egrep (bsc#1179045) egrep is only a deprecated bash wrapper for 'grep -E'. So use the latter instead.
- rpm/kernel-module-subpackage: make Group tag optional (bsc#1163592)
- rpm/kernel-obs-build.spec.in: Add -q option to modprobe calls (bsc#1178401)
- rpm/kernel-{source,binary}.spec: do not include ghost symlinks (boo#1179082).
- rpm/mkspec: do not build kernel-obs-build on x86_32 We want to use 64bit kernel due to various bugs (bsc#1178762 to name one). There is: ExportFilter: ^kernel-obs-build.*\.x86_64.rpm$ . i586 in Factory's prjconf now. No other actively maintained distro (i.e. merging packaging branch) builds a x86_32 kernel, hence pushing to packaging directly.
- rpm/post.sh: Avoid purge-kernel for the first installed kernel (bsc#1180058)
- scripts/lib/SUSE/MyBS.pm: properly close prjconf Macros: section
- scsi: fc: add FPIN ELS definition (bsc#1181441).
- scsi/fc: kABI fixes for new ELS_FPIN definition (bsc#1181441)
- scsi: fc: Update Descriptor definition and add RDF and Link Integrity FPINs (bsc#1181441).
- scsi: Fix trivial spelling (bsc#1181441).
- scsi: qla2xxx: Add IOCB resource tracking (bsc#1181441).
- ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'Linux Kernel' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server for SAP Applications 12-SP4.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"kernel-default", rpm:"kernel-default~4.12.14~95.71.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-base", rpm:"kernel-default-base~4.12.14~95.71.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-devel", rpm:"kernel-default-devel~4.12.14~95.71.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-default-man", rpm:"kernel-default-man~4.12.14~95.71.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-devel", rpm:"kernel-devel~4.12.14~95.71.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-macros", rpm:"kernel-macros~4.12.14~95.71.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-source", rpm:"kernel-source~4.12.14~95.71.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-syms", rpm:"kernel-syms~4.12.14~95.71.1", rls:"SLES12.0SP4"))) {
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
