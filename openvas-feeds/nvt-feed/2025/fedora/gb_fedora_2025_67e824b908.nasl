# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.6710182498908");
  script_cve_id("CVE-2025-32050", "CVE-2025-32052", "CVE-2025-32053", "CVE-2025-32906", "CVE-2025-32907", "CVE-2025-32909", "CVE-2025-32910", "CVE-2025-32911", "CVE-2025-32913");
  script_tag(name:"creation_date", value:"2025-04-25 04:05:02 +0000 (Fri, 25 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 16:16:06 +0000 (Tue, 15 Apr 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-67e824b908)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-67e824b908");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-67e824b908");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357079");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357086");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2357088");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2359346");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2359351");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2359361");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2359364");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2359367");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2359370");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw-libsoup' package(s) announced via the FEDORA-2025-67e824b908 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Backport fixes for CVE-2025-32910, CVE-2025-32911, CVE-2025-32913

----

Backport fixes for CVE-2025-32050 CVE-2025-32052 CVE-2025-32053 CVE-2025-32906
 CVE-2025-32907 CVE-2025-32909");

  script_tag(name:"affected", value:"'mingw-libsoup' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"mingw-libsoup", rpm:"mingw-libsoup~2.74.3~11.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-libsoup", rpm:"mingw32-libsoup~2.74.3~11.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-libsoup-debuginfo", rpm:"mingw32-libsoup-debuginfo~2.74.3~11.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-libsoup", rpm:"mingw64-libsoup~2.74.3~11.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw64-libsoup-debuginfo", rpm:"mingw64-libsoup-debuginfo~2.74.3~11.fc40", rls:"FC40"))) {
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
