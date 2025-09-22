# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856823");
  script_cve_id("CVE-2024-11403");
  script_tag(name:"creation_date", value:"2024-12-10 05:00:23 +0000 (Tue, 10 Dec 2024)");
  script_version("2025-07-24T05:43:49+0000");
  script_tag(name:"last_modification", value:"2025-07-24 05:43:49 +0000 (Thu, 24 Jul 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-23 19:48:17 +0000 (Wed, 23 Jul 2025)");

  script_name("openSUSE Security Advisory (openSUSE-SU-2024:0402-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.5");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2024:0402-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/TGCRWIE4IMT4IZHYUTUPMPDFR46SJODV/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1233764");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt6-webengine' package(s) announced via the openSUSE-SU-2024:0402-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qt6-webengine fixes the following issues:

- CVE-2024-11403: Fixed out of bounds memory read/write in libjxl (boo#1233764)");

  script_tag(name:"affected", value:"'qt6-webengine' package(s) on openSUSE Leap 15.5.");

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

if(release == "openSUSELeap15.5") {

  if(!isnull(res = isrpmvuln(pkg:"libQt6Pdf6", rpm:"libQt6Pdf6~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6PdfQuick6", rpm:"libQt6PdfQuick6~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6PdfWidgets6", rpm:"libQt6PdfWidgets6~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6WebEngineCore6", rpm:"libQt6WebEngineCore6~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6WebEngineQuick6", rpm:"libQt6WebEngineQuick6~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6WebEngineWidgets6", rpm:"libQt6WebEngineWidgets6~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-pdf-devel", rpm:"qt6-pdf-devel~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-pdf-imports", rpm:"qt6-pdf-imports~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-pdf-private-devel", rpm:"qt6-pdf-private-devel~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-pdfquick-devel", rpm:"qt6-pdfquick-devel~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-pdfquick-private-devel", rpm:"qt6-pdfquick-private-devel~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-pdfwidgets-devel", rpm:"qt6-pdfwidgets-devel~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-pdfwidgets-private-devel", rpm:"qt6-pdfwidgets-private-devel~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webengine", rpm:"qt6-webengine~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webengine-docs-html", rpm:"qt6-webengine-docs-html~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webengine-docs-qch", rpm:"qt6-webengine-docs-qch~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webengine-examples", rpm:"qt6-webengine-examples~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webengine-imports", rpm:"qt6-webengine-imports~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webenginecore-devel", rpm:"qt6-webenginecore-devel~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webenginecore-private-devel", rpm:"qt6-webenginecore-private-devel~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webenginequick-devel", rpm:"qt6-webenginequick-devel~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webenginequick-private-devel", rpm:"qt6-webenginequick-private-devel~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webenginewidgets-devel", rpm:"qt6-webenginewidgets-devel~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webenginewidgets-private-devel", rpm:"qt6-webenginewidgets-private-devel~6.4.2~bp155.2.6.1", rls:"openSUSELeap15.5"))) {
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
