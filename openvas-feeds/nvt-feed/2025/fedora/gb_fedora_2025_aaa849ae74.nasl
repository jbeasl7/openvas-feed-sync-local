# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.9797978499710174");
  script_cve_id("CVE-2023-48795", "CVE-2023-6918");
  script_tag(name:"creation_date", value:"2025-03-31 04:04:47 +0000 (Mon, 31 Mar 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 18:26:44 +0000 (Thu, 28 Dec 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2025-aaa849ae74)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-aaa849ae74");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-aaa849ae74");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254210");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2254997");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255048");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2255160");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libssh2' package(s) announced via the FEDORA-2025-aaa849ae74 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update, to the current upstream libssh2 release, addresses a couple of security issues:

 * CVE-2023-6918 (missing checks for return values for digests)
 * CVE-2023-48795 (prefix truncation attack on Binary Packet Protocol (BPP) - 'Terrapin')

It also removes support for a number of legacy algorithms that were disabled by default or removed from OpenSSH in the 2015-2018 time period. See the `RELEASE_NOTES` file for full details.

In addition, there are a large number of bug fixes and enhancements, which again are described in the `RELEASE_NOTES` file.");

  script_tag(name:"affected", value:"'libssh2' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"libssh2", rpm:"libssh2~1.11.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-debuginfo", rpm:"libssh2-debuginfo~1.11.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-debugsource", rpm:"libssh2-debugsource~1.11.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-devel", rpm:"libssh2-devel~1.11.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libssh2-docs", rpm:"libssh2-docs~1.11.1~1.fc40", rls:"FC40"))) {
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
