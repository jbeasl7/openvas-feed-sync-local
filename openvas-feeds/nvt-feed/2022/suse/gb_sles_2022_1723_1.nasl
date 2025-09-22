# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.1723.1");
  script_cve_id("CVE-2019-10871", "CVE-2019-10872", "CVE-2019-14494", "CVE-2019-7310", "CVE-2019-9631", "CVE-2019-9903", "CVE-2019-9959", "CVE-2020-27778");
  script_tag(name:"creation_date", value:"2022-05-19 04:28:35 +0000 (Thu, 19 May 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-08 12:59:24 +0000 (Fri, 08 Mar 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:1723-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1723-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20221723-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1124150");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1129202");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1130229");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1131722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1142465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1143950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1179163");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-May/011077.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler' package(s) announced via the SUSE-SU-2022:1723-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for poppler fixes the following issues:

- CVE-2020-27778: Fixed a buffer overflow in pdftohtml (bsc#1179163).
- CVE-2019-14494: Fixed a divide-by-zero error in pdftoppm (bsc#1143950).
- CVE-2019-9959: Fixed an integer overflow in pdftocairo (bsc#1142465).
- CVE-2019-10871: Fixed an invalid memory access in pdftops (bsc#1131696).
- CVE-2019-10872: Fixed an invalid memory access in pdftoppm (bsc#1131722).
- CVE-2019-9903: Fixed a buffer overflow in pdfunite (bsc#1130229).
- CVE-2019-7310: Fixed an application crash in pdftocairo (bsc#1124150).
- CVE-2019-9631: Fixed an invalid memory access in pdftocairo (bsc#1129202).");

  script_tag(name:"affected", value:"'poppler' package(s) on SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-glib8", rpm:"libpoppler-glib8~0.43.0~16.19.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler-qt4-4", rpm:"libpoppler-qt4-4~0.43.0~16.19.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpoppler60", rpm:"libpoppler60~0.43.0~16.19.3", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-tools", rpm:"poppler-tools~0.43.0~16.19.3", rls:"SLES12.0SP5"))) {
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
