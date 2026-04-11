# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.4440980010125");
  script_cve_id("CVE-2025-49010", "CVE-2025-66037", "CVE-2025-66038", "CVE-2025-66215");
  script_tag(name:"creation_date", value:"2026-04-09 04:50:45 +0000 (Thu, 09 Apr 2026)");
  script_version("2026-04-09T06:11:03+0000");
  script_tag(name:"last_modification", value:"2026-04-09 06:11:03 +0000 (Thu, 09 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-04-01 17:28:49 +0000 (Wed, 01 Apr 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-4440b00e25)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-4440b00e25");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-4440b00e25");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2442363");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2453188");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2453189");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2453190");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2453191");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'opensc' package(s) announced via the FEDORA-2026-4440b00e25 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New upstream release (#2442363) fixing various security issues:");

  script_tag(name:"affected", value:"'opensc' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"opensc", rpm:"opensc~0.27.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-debuginfo", rpm:"opensc-debuginfo~0.27.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-debugsource", rpm:"opensc-debugsource~0.27.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-libs", rpm:"opensc-libs~0.27.1~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"opensc-libs-debuginfo", rpm:"opensc-libs-debuginfo~0.27.1~1.fc43", rls:"FC43"))) {
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
