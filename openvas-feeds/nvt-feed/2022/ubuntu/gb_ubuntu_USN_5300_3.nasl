# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845270");
  script_cve_id("CVE-2017-8923", "CVE-2017-9118", "CVE-2017-9120", "CVE-2021-21707");
  script_tag(name:"creation_date", value:"2022-03-08 02:01:09 +0000 (Tue, 08 Mar 2022)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-01 02:07:55 +0000 (Mon, 01 Oct 2018)");

  script_name("Ubuntu: Security Advisory (USN-5300-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU21\.10");

  script_xref(name:"Advisory-ID", value:"USN-5300-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5300-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php8.0' package(s) announced via the USN-5300-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5300-1 fixed vulnerabilities in PHP. This update provides the
corresponding updates for Ubuntu 21.10.

Original advisory details:

 It was discovered that PHP incorrectly handled certain scripts.
 An attacker could possibly use this issue to cause a denial of service.
 (CVE-2015-9253, CVE-2017-8923, CVE-2017-9118, CVE-2017-9120)

 It was discovered that PHP incorrectly handled certain inputs.
 An attacker could possibly use this issue to cause a denial of service,
 or possibly obtain sensitive information. (CVE-2017-9119)

 It was discovered that PHP incorrectly handled certain scripts with XML
 parsing functions.
 An attacker could possibly use this issue to obtain sensitive information.
 (CVE-2021-21707)");

  script_tag(name:"affected", value:"'php8.0' package(s) on Ubuntu 21.10.");

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

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"php8.0-cgi", ver:"8.0.8-1ubuntu0.3", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.0-cli", ver:"8.0.8-1ubuntu0.3", rls:"UBUNTU21.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php8.0-fpm", ver:"8.0.8-1ubuntu0.3", rls:"UBUNTU21.10"))) {
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
