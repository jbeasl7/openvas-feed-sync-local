# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0736.1");
  script_cve_id("CVE-2021-3778", "CVE-2021-3796", "CVE-2021-3872", "CVE-2021-3927", "CVE-2021-3928", "CVE-2021-3984", "CVE-2021-4019", "CVE-2021-4193", "CVE-2021-46059", "CVE-2022-0318", "CVE-2022-0319", "CVE-2022-0351", "CVE-2022-0361", "CVE-2022-0413");
  script_tag(name:"creation_date", value:"2022-03-05 04:11:51 +0000 (Sat, 05 Mar 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-27 14:17:44 +0000 (Thu, 27 Jan 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0736-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0736-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220736-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190533");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1190570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191893");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192478");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192481");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193298");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195066");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195126");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195356");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-March/010366.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the SUSE-SU-2022:0736-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vim fixes the following issues:

- CVE-2022-0318: Fixed heap-based buffer overflow (bsc#1195004).
- CVE-2021-3796: Fixed use-after-free in nv_replace() in normal.c (bsc#1190570).
- CVE-2021-3872: Fixed heap-based buffer overflow in win_redr_status() drawscreen.c (bsc#1191893).
- CVE-2021-3927: Fixed heap-based buffer overflow (bsc#1192481).
- CVE-2021-3928: Fixed stack-based buffer overflow (bsc#1192478).
- CVE-2021-4019: Fixed heap-based buffer overflow (bsc#1193294).
- CVE-2021-3984: Fixed illegal memory access when C-indenting could have led to heap buffer overflow (bsc#1193298).
- CVE-2021-3778: Fixed heap-based buffer overflow in regexp_nfa.c (bsc#1190533).
- CVE-2021-4193: Fixed out-of-bounds read (bsc#1194216).
- CVE-2021-46059: Fixed pointer dereference vulnerability via the vim_regexec_multi function at regexp.c (bsc#1194556).
- CVE-2022-0319: Fixded out-of-bounds read (bsc#1195066).
- CVE-2022-0351: Fixed uncontrolled recursion in eval7() (bsc#1195126).
- CVE-2022-0361: Fixed buffer overflow (bsc#1195126).
- CVE-2022-0413: Fixed use-after-free in src/ex_cmds.c (bsc#1195356).");

  script_tag(name:"affected", value:"'vim' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15, SUSE Linux Enterprise Server for SAP Applications 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.0.1568~5.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~8.0.1568~5.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~8.0.1568~5.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~8.0.1568~5.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~8.0.1568~5.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~8.0.1568~5.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small-debuginfo", rpm:"vim-small-debuginfo~8.0.1568~5.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~8.0.1568~5.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~8.0.1568~5.17.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.0.1568~5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~8.0.1568~5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~8.0.1568~5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~8.0.1568~5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~8.0.1568~5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~8.0.1568~5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small-debuginfo", rpm:"vim-small-debuginfo~8.0.1568~5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~8.0.1568~5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~8.0.1568~5.17.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~8.0.1568~5.17.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.0.1568~5.17.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~8.0.1568~5.17.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~8.0.1568~5.17.1", rls:"SLES15.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~8.0.1568~5.17.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.0.1568~5.17.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~8.0.1568~5.17.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~8.0.1568~5.17.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~8.0.1568~5.17.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.0.1568~5.17.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~8.0.1568~5.17.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~8.0.1568~5.17.1", rls:"SLES15.0SP2"))) {
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
