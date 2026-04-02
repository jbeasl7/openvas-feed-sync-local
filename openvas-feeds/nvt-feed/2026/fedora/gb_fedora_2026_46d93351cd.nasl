# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.461009335199100");
  script_cve_id("CVE-2025-9301");
  script_tag(name:"creation_date", value:"2026-03-24 04:40:04 +0000 (Tue, 24 Mar 2026)");
  script_version("2026-03-24T05:57:14+0000");
  script_tag(name:"last_modification", value:"2026-03-24 05:57:14 +0000 (Tue, 24 Mar 2026)");
  script_tag(name:"cvss_base", value:"1.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-08-21 14:15:44 +0000 (Thu, 21 Aug 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2026-46d93351cd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-46d93351cd");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-46d93351cd");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2390122");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cmake' package(s) announced via the FEDORA-2026-46d93351cd advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update to v3.31.11.");

  script_tag(name:"affected", value:"'cmake' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"cmake", rpm:"cmake~3.31.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cmake-data", rpm:"cmake-data~3.31.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cmake-debuginfo", rpm:"cmake-debuginfo~3.31.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cmake-debugsource", rpm:"cmake-debugsource~3.31.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cmake-doc", rpm:"cmake-doc~3.31.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cmake-filesystem", rpm:"cmake-filesystem~3.31.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cmake-gui", rpm:"cmake-gui~3.31.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cmake-gui-debuginfo", rpm:"cmake-gui-debuginfo~3.31.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cmake-rpm-macros", rpm:"cmake-rpm-macros~3.31.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cmake-srpm-macros", rpm:"cmake-srpm-macros~3.31.11~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cmake", rpm:"python3-cmake~3.31.11~1.fc43", rls:"FC43"))) {
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
