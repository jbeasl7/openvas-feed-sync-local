# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.845432");
  script_cve_id("CVE-2022-31625");
  script_tag(name:"creation_date", value:"2022-07-08 01:00:37 +0000 (Fri, 08 Jul 2022)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 17:08:01 +0000 (Mon, 27 Jun 2022)");

  script_name("Ubuntu: Security Advisory (USN-5479-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU18\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-5479-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5479-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7.2' package(s) announced via the USN-5479-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-5479-1 fixed vulnerabilities in PHP. Unfortunately that update for
CVE-2022-31625 was incomplete for Ubuntu 18.04 LTS. This update fixes
the problem.

We apologize for the inconvenience.

Original advisory details:

 Charles Fol discovered that PHP incorrectly handled initializing certain
 arrays when handling the pg_query_params function. A remote attacker could
 use this issue to cause PHP to crash, resulting in a denial of service, or
 possibly execute arbitrary code. (CVE-2022-31625)

 Charles Fol discovered that PHP incorrectly handled passwords in mysqlnd. A
 remote attacker could use this issue to cause PHP to crash, resulting in a
 denial of service, or possibly execute arbitrary code. (CVE-2022-31626)");

  script_tag(name:"affected", value:"'php7.2' package(s) on Ubuntu 18.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php7.2", ver:"7.2.24-0ubuntu0.18.04.13", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.2-cgi", ver:"7.2.24-0ubuntu0.18.04.13", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.2-cli", ver:"7.2.24-0ubuntu0.18.04.13", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.2-fpm", ver:"7.2.24-0ubuntu0.18.04.13", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.2-pgsql", ver:"7.2.24-0ubuntu0.18.04.13", rls:"UBUNTU18.04 LTS"))) {
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
