# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.19947101433100102");
  script_cve_id("CVE-2025-6966");
  script_tag(name:"creation_date", value:"2026-03-04 04:36:20 +0000 (Wed, 04 Mar 2026)");
  script_version("2026-03-05T05:55:06+0000");
  script_tag(name:"last_modification", value:"2026-03-05 05:55:06 +0000 (Thu, 05 Mar 2026)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-07 22:20:56 +0000 (Wed, 07 Jan 2026)");

  script_name("Fedora: Security Advisory (FEDORA-2026-1c47e433df)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-1c47e433df");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-1c47e433df");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2149769");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2319327");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2339898");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2384459");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2423062");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apt, python-apt' package(s) announced via the FEDORA-2026-1c47e433df advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to latest upstream release apt 3.1.15 and python-apt 3.1.0

----

Update to latest upstream release apt 3.1.15, also fix build problem with previous release");

  script_tag(name:"affected", value:"'apt, python-apt' package(s) on Fedora 43.");

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

  if(!isnull(res = isrpmvuln(pkg:"apt", rpm:"apt~3.1.15~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apt-apidoc", rpm:"apt-apidoc~3.1.15~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apt-debuginfo", rpm:"apt-debuginfo~3.1.15~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apt-debugsource", rpm:"apt-debugsource~3.1.15~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apt-devel", rpm:"apt-devel~3.1.15~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apt-doc", rpm:"apt-doc~3.1.15~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apt-libs", rpm:"apt-libs~3.1.15~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apt-libs-debuginfo", rpm:"apt-libs-debuginfo~3.1.15~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apt-utils", rpm:"apt-utils~3.1.15~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apt-utils-debuginfo", rpm:"apt-utils-debuginfo~3.1.15~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-apt", rpm:"python-apt~3.1.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-apt-debugsource", rpm:"python-apt-debugsource~3.1.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-apt", rpm:"python3-apt~3.1.0~1.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-apt-debuginfo", rpm:"python3-apt-debuginfo~3.1.0~1.fc43", rls:"FC43"))) {
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
