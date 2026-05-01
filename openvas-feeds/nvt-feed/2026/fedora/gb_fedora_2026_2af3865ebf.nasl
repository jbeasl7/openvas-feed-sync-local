# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.297102386510198102");
  script_cve_id("CVE-2025-8869", "CVE-2026-25645");
  script_tag(name:"creation_date", value:"2026-04-16 05:05:42 +0000 (Thu, 16 Apr 2026)");
  script_version("2026-04-16T06:18:46+0000");
  script_tag(name:"last_modification", value:"2026-04-16 06:18:46 +0000 (Thu, 16 Apr 2026)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-30 14:23:16 +0000 (Mon, 30 Mar 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-2af3865ebf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-2af3865ebf");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-2af3865ebf");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2397929");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2452324");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pypy' package(s) announced via the FEDORA-2026-2af3865ebf advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"JIT translation fix for bootstraping, require openssl 3 and fix CVE-2026-25645 and CVE-2025-8869");

  script_tag(name:"affected", value:"'pypy' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"pypy", rpm:"pypy~7.3.21~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy-debuginfo", rpm:"pypy-debuginfo~7.3.21~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy-debugsource", rpm:"pypy-debugsource~7.3.21~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy-debugsource-debuginfo", rpm:"pypy-debugsource-debuginfo~7.3.21~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy-devel", rpm:"pypy-devel~7.3.21~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy-libs", rpm:"pypy-libs~7.3.21~8.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pypy-libs-debuginfo", rpm:"pypy-libs-debuginfo~7.3.21~8.fc43", rls:"FC43"))) {
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
