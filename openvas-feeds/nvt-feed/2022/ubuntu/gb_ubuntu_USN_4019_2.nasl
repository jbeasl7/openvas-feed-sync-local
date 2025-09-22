# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2019.4019.2");
  script_cve_id("CVE-2016-6153", "CVE-2017-10989", "CVE-2017-13685", "CVE-2017-2518", "CVE-2018-20346", "CVE-2018-20506", "CVE-2019-8457");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-30 18:53:31 +0000 (Thu, 30 May 2019)");

  script_name("Ubuntu: Security Advisory (USN-4019-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4019-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4019-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sqlite3' package(s) announced via the USN-4019-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4019-1 fixed several vulnerabilities in sqlite3. This update provides
the corresponding update for Ubuntu 12.04 ESM and 14.04 ESM.

Original advisory details:

 It was discovered that SQLite incorrectly handled certain SQL files.
 An attacker could possibly use this issue to execute arbitrary code
 or cause a denial of service. (CVE-2017-2518)

 It was discovered that SQLite incorrectly handled certain queries.
 An attacker could possibly use this issue to execute arbitrary code.
 (CVE-2018-20346, CVE-2018-20506)

 It was discovered that SQLite incorrectly handled certain inputs.
 An attacker could possibly use this issue to access sensitive information.
 (CVE-2019-8457)

 It was discovered that SQLite incorrectly handled certain inputs.
 An attacker could possibly use this issue to cause a denial of service.
 (CVE-2016-6153)

 It was discovered that SQLite incorrectly handled certain databases.
 An attacker could possibly use this issue to access sensitive information.
 This issue only affected Ubuntu 14.04 LTS. (CVE-2017-10989)

 It was discovered that SQLite incorrectly handled certain files.
 An attacker could possibly use this issue to cause a denial of service.
 (CVE-2017-13685)");

  script_tag(name:"affected", value:"'sqlite3' package(s) on Ubuntu 12.04, Ubuntu 14.04.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-0", ver:"3.7.9-2ubuntu1.3", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sqlite3", ver:"3.7.9-2ubuntu1.3", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libsqlite3-0", ver:"3.8.2-1ubuntu2.2+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sqlite3", ver:"3.8.2-1ubuntu2.2+esm1", rls:"UBUNTU14.04 LTS"))) {
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
