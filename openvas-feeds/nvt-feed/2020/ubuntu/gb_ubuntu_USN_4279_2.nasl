# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.844349");
  script_cve_id("CVE-2015-9253", "CVE-2020-7059", "CVE-2020-7060");
  script_tag(name:"creation_date", value:"2020-02-20 04:00:23 +0000 (Thu, 20 Feb 2020)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-11 17:46:09 +0000 (Tue, 11 Feb 2020)");

  script_name("Ubuntu: Security Advisory (USN-4279-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU16\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4279-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4279-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1863850");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php7.0' package(s) announced via the USN-4279-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4279-1 fixed vulnerabilities in PHP. The updated packages caused a regression.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that PHP incorrectly handled certain scripts.
 An attacker could possibly use this issue to cause a denial of service.
 This issue only affected Ubuntu 12.04 ESM, Ubuntu 14.04 ESM and Ubuntu 16.04 LTS.
 (CVE-2015-9253)

 It was discovered that PHP incorrectly handled certain inputs. An attacker
 could possibly use this issue to expose sensitive information.
 (CVE-2020-7059)

 It was discovered that PHP incorrectly handled certain inputs.
 An attacker could possibly use this issue to execute arbitrary code.
 This issue only affected Ubuntu 14.04 ESM, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS
 and Ubuntu 19.10. (CVE-2020-7060)");

  script_tag(name:"affected", value:"'php7.0' package(s) on Ubuntu 16.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libapache2-mod-php7.0", ver:"7.0.33-0ubuntu0.16.04.12", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.0-cgi", ver:"7.0.33-0ubuntu0.16.04.12", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.0-cli", ver:"7.0.33-0ubuntu0.16.04.12", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"php7.0-fpm", ver:"7.0.33-0ubuntu0.16.04.12", rls:"UBUNTU16.04 LTS"))) {
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
