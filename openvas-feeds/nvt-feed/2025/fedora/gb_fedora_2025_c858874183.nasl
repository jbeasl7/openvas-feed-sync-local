# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.99858874183");
  script_cve_id("CVE-2024-34459");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:44+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:44 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2025-c858874183)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-c858874183");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-c858874183");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280538");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt6-qtwebengine' package(s) announced via the FEDORA-2025-c858874183 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Unbundle libxml2.");

  script_tag(name:"affected", value:"'qt6-qtwebengine' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpdf", rpm:"qt6-qtpdf~6.8.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpdf-debuginfo", rpm:"qt6-qtpdf-debuginfo~6.8.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpdf-devel", rpm:"qt6-qtpdf-devel~6.8.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpdf-examples", rpm:"qt6-qtpdf-examples~6.8.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtpdf-examples-debuginfo", rpm:"qt6-qtpdf-examples-debuginfo~6.8.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine", rpm:"qt6-qtwebengine~6.8.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine-debuginfo", rpm:"qt6-qtwebengine-debuginfo~6.8.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine-debugsource", rpm:"qt6-qtwebengine-debugsource~6.8.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine-devel", rpm:"qt6-qtwebengine-devel~6.8.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine-devel-debuginfo", rpm:"qt6-qtwebengine-devel-debuginfo~6.8.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine-devtools", rpm:"qt6-qtwebengine-devtools~6.8.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine-examples", rpm:"qt6-qtwebengine-examples~6.8.2~4.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-qtwebengine-examples-debuginfo", rpm:"qt6-qtwebengine-examples-debuginfo~6.8.2~4.fc41", rls:"FC41"))) {
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
