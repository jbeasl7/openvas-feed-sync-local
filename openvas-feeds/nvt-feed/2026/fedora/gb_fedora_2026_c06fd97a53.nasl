# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.9906102100979753");
  script_cve_id("CVE-2026-25556");
  script_tag(name:"creation_date", value:"2026-02-23 04:44:29 +0000 (Mon, 23 Feb 2026)");
  script_version("2026-02-25T05:57:40+0000");
  script_tag(name:"last_modification", value:"2026-02-25 05:57:40 +0000 (Wed, 25 Feb 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-24 21:07:13 +0000 (Tue, 24 Feb 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-c06fd97a53)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-c06fd97a53");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-c06fd97a53");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2437972");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mupdf, python-PyMuPDF, qpdfview, zathura-pdf-mupdf' package(s) announced via the FEDORA-2026-c06fd97a53 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"mupdf 1.27.1 and dependencies");

  script_tag(name:"affected", value:"'mupdf, python-PyMuPDF, qpdfview, zathura-pdf-mupdf' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"mupdf", rpm:"mupdf~1.27.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mupdf-cpp-devel", rpm:"mupdf-cpp-devel~1.27.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mupdf-cpp-libs", rpm:"mupdf-cpp-libs~1.27.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mupdf-debugsource", rpm:"mupdf-debugsource~1.27.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mupdf-devel", rpm:"mupdf-devel~1.27.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mupdf-libs", rpm:"mupdf-libs~1.27.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-PyMuPDF", rpm:"python-PyMuPDF~1.27.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-PyMuPDF-debugsource", rpm:"python-PyMuPDF-debugsource~1.27.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-PyMuPDF-doc", rpm:"python-PyMuPDF-doc~1.27.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-PyMuPDF", rpm:"python3-PyMuPDF~1.27.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-PyMuPDF-debuginfo", rpm:"python3-PyMuPDF-debuginfo~1.27.1~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mupdf", rpm:"python3-mupdf~1.27.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mupdf-debuginfo", rpm:"python3-mupdf-debuginfo~1.27.1~4.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpdfview", rpm:"qpdfview~0.5.0~25.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpdfview-debuginfo", rpm:"qpdfview-debuginfo~0.5.0~25.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qpdfview-debugsource", rpm:"qpdfview-debugsource~0.5.0~25.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zathura-pdf-mupdf", rpm:"zathura-pdf-mupdf~0.4.4~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zathura-pdf-mupdf-debuginfo", rpm:"zathura-pdf-mupdf-debuginfo~0.4.4~9.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zathura-pdf-mupdf-debugsource", rpm:"zathura-pdf-mupdf-debugsource~0.4.4~9.fc43", rls:"FC43"))) {
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
