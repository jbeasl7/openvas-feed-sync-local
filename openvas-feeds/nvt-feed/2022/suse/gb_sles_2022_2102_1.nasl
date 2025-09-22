# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2102.1");
  script_cve_id("CVE-2017-17087", "CVE-2021-3778", "CVE-2021-3796", "CVE-2021-3872", "CVE-2021-3875", "CVE-2021-3903", "CVE-2021-3927", "CVE-2021-3928", "CVE-2021-3968", "CVE-2021-3973", "CVE-2021-3974", "CVE-2021-3984", "CVE-2021-4019", "CVE-2021-4069", "CVE-2021-4136", "CVE-2021-4166", "CVE-2021-4192", "CVE-2021-4193", "CVE-2021-46059", "CVE-2022-0128", "CVE-2022-0213", "CVE-2022-0261", "CVE-2022-0318", "CVE-2022-0319", "CVE-2022-0351", "CVE-2022-0359", "CVE-2022-0361", "CVE-2022-0392", "CVE-2022-0407", "CVE-2022-0413", "CVE-2022-0696", "CVE-2022-1381", "CVE-2022-1420", "CVE-2022-1616", "CVE-2022-1619", "CVE-2022-1620", "CVE-2022-1733", "CVE-2022-1735", "CVE-2022-1771", "CVE-2022-1785", "CVE-2022-1796", "CVE-2022-1851", "CVE-2022-1897", "CVE-2022-1898", "CVE-2022-1927");
  script_tag(name:"creation_date", value:"2022-06-17 04:28:40 +0000 (Fri, 17 Jun 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-27 14:17:44 +0000 (Thu, 27 Jan 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2102-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2102-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222102-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1070955");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1191770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192167");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192902");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192903");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1192904");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193466");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194093");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194216");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194388");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194872");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1194885");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195004");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195203");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195354");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1196361");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1198748");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199331");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199333");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199334");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199651");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199655");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199693");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199745");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199747");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199936");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200010");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200011");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1200012");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-June/011301.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the SUSE-SU-2022:2102-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vim fixes the following issues:

- CVE-2017-17087: Fixed information leak via .swp files (bsc#1070955).
- CVE-2021-3875: Fixed heap-based buffer overflow (bsc#1191770).
- CVE-2021-3903: Fixed heap-based buffer overflow (bsc#1192167).
- CVE-2021-3968: Fixed heap-based buffer overflow (bsc#1192902).
- CVE-2021-3973: Fixed heap-based buffer overflow (bsc#1192903).
- CVE-2021-3974: Fixed use-after-free (bsc#1192904).
- CVE-2021-4069: Fixed use-after-free in ex_open()in src/ex_docmd.c (bsc#1193466).
- CVE-2021-4136: Fixed heap-based buffer overflow (bsc#1193905).
- CVE-2021-4166: Fixed out-of-bounds read (bsc#1194093).
- CVE-2021-4192: Fixed use-after-free (bsc#1194217).
- CVE-2021-4193: Fixed out-of-bounds read (bsc#1194216).
- CVE-2022-0128: Fixed out-of-bounds read (bsc#1194388).
- CVE-2022-0213: Fixed heap-based buffer overflow (bsc#1194885).
- CVE-2022-0261: Fixed heap-based buffer overflow (bsc#1194872).
- CVE-2022-0318: Fixed heap-based buffer overflow (bsc#1195004).
- CVE-2022-0359: Fixed heap-based buffer overflow in init_ccline() in ex_getln.c (bsc#1195203).
- CVE-2022-0392: Fixed heap-based buffer overflow (bsc#1195332).
- CVE-2022-0407: Fixed heap-based buffer overflow (bsc#1195354).
- CVE-2022-0696: Fixed NULL pointer dereference (bsc#1196361).
- CVE-2022-1381: Fixed global heap buffer overflow in skip_range (bsc#1198596).
- CVE-2022-1420: Fixed out-of-range pointer offset (bsc#1198748).
- CVE-2022-1616: Fixed use-after-free in append_command (bsc#1199331).
- CVE-2022-1619: Fixed heap-based Buffer Overflow in function cmdline_erase_chars (bsc#1199333).
- CVE-2022-1620: Fixed NULL pointer dereference in function vim_regexec_string (bsc#1199334).
- CVE-2022-1733: Fixed heap-based buffer overflow in cindent.c (bsc#1199655).
- CVE-2022-1735: Fixed heap-based buffer overflow (bsc#1199651).
- CVE-2022-1771: Fixed stack exhaustion (bsc#1199693).
- CVE-2022-1785: Fixed out-of-bounds write (bsc#1199745).
- CVE-2022-1796: Fixed use-after-free in find_pattern_in_path (bsc#1199747).
- CVE-2022-1851: Fixed out-of-bounds read (bsc#1199936).
- CVE-2022-1897: Fixed out-of-bounds write (bsc#1200010).
- CVE-2022-1898: Fixed use-after-free (bsc#1200011).
- CVE-2022-1927: Fixed buffer over-read (bsc#1200012).");

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

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.2.5038~150000.5.21.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~8.2.5038~150000.5.21.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~8.2.5038~150000.5.21.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~8.2.5038~150000.5.21.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~8.2.5038~150000.5.21.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~8.2.5038~150000.5.21.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small-debuginfo", rpm:"vim-small-debuginfo~8.2.5038~150000.5.21.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~8.2.5038~150000.5.21.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~8.2.5038~150000.5.21.1", rls:"SLES15.0SP3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.2.5038~150000.5.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~8.2.5038~150000.5.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~8.2.5038~150000.5.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debuginfo", rpm:"vim-debuginfo~8.2.5038~150000.5.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-debugsource", rpm:"vim-debugsource~8.2.5038~150000.5.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small", rpm:"vim-small~8.2.5038~150000.5.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-small-debuginfo", rpm:"vim-small-debuginfo~8.2.5038~150000.5.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~8.2.5038~150000.5.21.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gvim-debuginfo", rpm:"gvim-debuginfo~8.2.5038~150000.5.21.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~8.2.5038~150000.5.21.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.2.5038~150000.5.21.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~8.2.5038~150000.5.21.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~8.2.5038~150000.5.21.1", rls:"SLES15.0"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~8.2.5038~150000.5.21.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.2.5038~150000.5.21.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~8.2.5038~150000.5.21.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~8.2.5038~150000.5.21.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"gvim", rpm:"gvim~8.2.5038~150000.5.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~8.2.5038~150000.5.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data", rpm:"vim-data~8.2.5038~150000.5.21.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-data-common", rpm:"vim-data-common~8.2.5038~150000.5.21.1", rls:"SLES15.0SP2"))) {
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
