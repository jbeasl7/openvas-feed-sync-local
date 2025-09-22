# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.3183.1");
  script_cve_id("CVE-2017-13728", "CVE-2017-13729", "CVE-2017-13730", "CVE-2017-13731", "CVE-2017-13732", "CVE-2017-13733", "CVE-2017-16879");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:50 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-06 14:08:22 +0000 (Wed, 06 Dec 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:3183-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:3183-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20173183-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056127");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056128");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056129");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056131");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056132");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1056136");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1069530");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-December/003468.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ncurses' package(s) announced via the SUSE-SU-2017:3183-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ncurses fixes the following issues:

Security issues fixed:

- CVE-2017-13728: Fix infinite loop in the next_char function in comp_scan.c (bsc#1056136).
- CVE-2017-13729: Fix illegal address access in the _nc_save_str (bsc#1056132).
- CVE-2017-13730: Fix illegal address access in the function _nc_read_entry_source() (bsc#1056131).
- CVE-2017-13731: Fix illegal address access in the function postprocess_termcap() (bsc#1056129).
- CVE-2017-13732: Fix illegal address access in the function dump_uses() (bsc#1056128).
- CVE-2017-13733: Fix illegal address access in the fmt_entry function (bsc#1056127).
- CVE-2017-16879: Fix stack-based buffer overflow in the _nc_write_entry() function (bsc#1069530).");

  script_tag(name:"affected", value:"'ncurses' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server for SAP Applications 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libncurses5-32bit", rpm:"libncurses5-32bit~5.6~93.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses5", rpm:"libncurses5~5.6~93.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses5-x86", rpm:"libncurses5-x86~5.6~93.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses6-32bit", rpm:"libncurses6-32bit~5.6~93.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses6", rpm:"libncurses6~5.6~93.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libncurses6-x86", rpm:"libncurses6-x86~5.6~93.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ncurses-devel-32bit", rpm:"ncurses-devel-32bit~5.6~93.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ncurses-devel", rpm:"ncurses-devel~5.6~93.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ncurses-utils", rpm:"ncurses-utils~5.6~93.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tack", rpm:"tack~5.6~93.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"terminfo", rpm:"terminfo~5.6~93.12.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"terminfo-base", rpm:"terminfo-base~5.6~93.12.1", rls:"SLES11.0SP4"))) {
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
