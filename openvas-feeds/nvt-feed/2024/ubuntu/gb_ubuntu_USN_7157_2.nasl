# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.7157.2");
  script_cve_id("CVE-2024-8932");
  script_tag(name:"creation_date", value:"2024-12-16 04:08:27 +0000 (Mon, 16 Dec 2024)");
  script_version("2024-12-17T05:05:41+0000");
  script_tag(name:"last_modification", value:"2024-12-17 05:05:41 +0000 (Tue, 17 Dec 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Ubuntu: Security Advisory (USN-7157-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-7157-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7157-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7.4' package(s) announced via the USN-7157-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-7157-1 fixed vulnerabilities in PHP. The patch for
CVE-2024-8932 caused a regression in php7.4. This
update fixes the problem.

Original advisory details:

 It was discovered that PHP incorrectly handled certain inputs when
 processed with convert.quoted-printable decode filters.
 An attacker could possibly use this issue to expose sensitive
 information or cause a crash. (CVE-2024-11233)

 It was discovered that PHP incorrectly handled certain HTTP requests.
 An attacker could possibly use this issue to performing arbitrary
 HTTP requests originating from the server, thus potentially
 gaining access to resources not normally available to the external
 user. (CVE-2024-11234)

 It was discovered that PHP incorrectly handled certain inputs.
 An attacker could possibly use this issue to cause a crash or
 execute arbitrary code. (CVE-2024-11236, CVE-2024-8932)

 It was discovered that PHP incorrectly handled certain MySQL requests.
 An attacker could possibly use this issue to cause the client to
 disclose the content of its heap containing data from other SQL requests
 and possible other data belonging to different users of the same server.
 (CVE-2024-8929)");

  script_tag(name:"affected", value:"'php7.4' package(s) on Ubuntu 20.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php7.4", ver:"7.4.3-4ubuntu2.28", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4", ver:"7.4.3-4ubuntu2.28", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-cgi", ver:"7.4.3-4ubuntu2.28", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-cli", ver:"7.4.3-4ubuntu2.28", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.4-ldap", ver:"7.4.3-4ubuntu2.28", rls:"UBUNTU20.04 LTS"))) {
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
