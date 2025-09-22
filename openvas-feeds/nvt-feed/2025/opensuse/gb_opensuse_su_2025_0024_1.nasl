# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0024.1");
  script_cve_id("CVE-2024-40896");
  script_tag(name:"creation_date", value:"2025-02-18 11:01:57 +0000 (Tue, 18 Feb 2025)");
  script_version("2025-02-20T08:47:14+0000");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0024-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0024-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/MJTWGGN25MWIFFI6LEBRJNH3QPOW4COP/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234820");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt6-webengine' package(s) announced via the openSUSE-SU-2025:0024-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qt6-webengine fixes the following issues:

- CVE-2024-40896: Fixed a XML external entity vulnerability related to libxml2 (boo#1234820)");

  script_tag(name:"affected", value:"'qt6-webengine' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"libQt6Pdf6", rpm:"libQt6Pdf6~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6PdfQuick6", rpm:"libQt6PdfQuick6~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6PdfWidgets6", rpm:"libQt6PdfWidgets6~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6WebEngineCore6", rpm:"libQt6WebEngineCore6~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6WebEngineQuick6", rpm:"libQt6WebEngineQuick6~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6WebEngineWidgets6", rpm:"libQt6WebEngineWidgets6~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-pdf-devel", rpm:"qt6-pdf-devel~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-pdf-imports", rpm:"qt6-pdf-imports~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-pdf-private-devel", rpm:"qt6-pdf-private-devel~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-pdfquick-devel", rpm:"qt6-pdfquick-devel~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-pdfquick-private-devel", rpm:"qt6-pdfquick-private-devel~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-pdfwidgets-devel", rpm:"qt6-pdfwidgets-devel~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-pdfwidgets-private-devel", rpm:"qt6-pdfwidgets-private-devel~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webengine", rpm:"qt6-webengine~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webengine-docs-html", rpm:"qt6-webengine-docs-html~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webengine-docs-qch", rpm:"qt6-webengine-docs-qch~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webengine-examples", rpm:"qt6-webengine-examples~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webengine-imports", rpm:"qt6-webengine-imports~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webenginecore-devel", rpm:"qt6-webenginecore-devel~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webenginecore-private-devel", rpm:"qt6-webenginecore-private-devel~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webenginequick-devel", rpm:"qt6-webenginequick-devel~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webenginequick-private-devel", rpm:"qt6-webenginequick-private-devel~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webenginewidgets-devel", rpm:"qt6-webenginewidgets-devel~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-webenginewidgets-private-devel", rpm:"qt6-webenginewidgets-private-devel~6.6.3~bp156.2.3.1", rls:"openSUSELeap15.6"))) {
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
