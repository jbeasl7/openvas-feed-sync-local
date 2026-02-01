# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.2999769451989");
  script_cve_id("CVE-2025-67268", "CVE-2025-67269");
  script_tag(name:"creation_date", value:"2026-01-15 04:21:16 +0000 (Thu, 15 Jan 2026)");
  script_version("2026-01-15T05:47:46+0000");
  script_tag(name:"last_modification", value:"2026-01-15 05:47:46 +0000 (Thu, 15 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-2ca69451b9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-2ca69451b9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-2ca69451b9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2426827");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2426828");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2426932");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2426933");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gpsd' package(s) announced via the FEDORA-2026-2ca69451b9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fixes for CVE-2025-67268 and CVE-2025-67269.");

  script_tag(name:"affected", value:"'gpsd' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"gpsd", rpm:"gpsd~3.26.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gpsd-clients", rpm:"gpsd-clients~3.26.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gpsd-clients-debuginfo", rpm:"gpsd-clients-debuginfo~3.26.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gpsd-compat", rpm:"gpsd-compat~3.26.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gpsd-debuginfo", rpm:"gpsd-debuginfo~3.26.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gpsd-debugsource", rpm:"gpsd-debugsource~3.26.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gpsd-devel", rpm:"gpsd-devel~3.26.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gpsd-libs", rpm:"gpsd-libs~3.26.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gpsd-libs-debuginfo", rpm:"gpsd-libs-debuginfo~3.26.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gpsd-qt", rpm:"gpsd-qt~3.26.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gpsd-qt-debuginfo", rpm:"gpsd-qt-debuginfo~3.26.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gpsd-qt-devel", rpm:"gpsd-qt-devel~3.26.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gpsd-xclients", rpm:"gpsd-xclients~3.26.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gpsd", rpm:"python3-gpsd~3.26.1~6.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-gpsd-debuginfo", rpm:"python3-gpsd-debuginfo~3.26.1~6.fc43", rls:"FC43"))) {
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
