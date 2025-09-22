# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.843501");
  script_cve_id("CVE-2018-5125", "CVE-2018-5126", "CVE-2018-5127", "CVE-2018-5128", "CVE-2018-5129", "CVE-2018-5130", "CVE-2018-5131", "CVE-2018-5132", "CVE-2018-5133", "CVE-2018-5134", "CVE-2018-5135", "CVE-2018-5136", "CVE-2018-5137", "CVE-2018-5140", "CVE-2018-5141", "CVE-2018-5142", "CVE-2018-5143");
  script_tag(name:"creation_date", value:"2018-04-07 04:15:50 +0000 (Sat, 07 Apr 2018)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-06 17:58:32 +0000 (Mon, 06 Aug 2018)");

  script_name("Ubuntu: Security Advisory (USN-3596-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-3596-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3596-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1758107");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-3596-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3596-1 fixed vulnerabilities in Firefox. The update caused an issue
where it was not possible to customize the toolbars when running Firefox
in Unity. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked in to opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service via application
 crash or opening new tabs, escape the sandbox, bypass same-origin
 restrictions, obtain sensitive information, confuse the user with
 misleading permission requests, or execute arbitrary code. (CVE-2018-5125,
 CVE-2018-5126, CVE-2018-5127, CVE-2018-5128, CVE-2018-5129, CVE-2018-5130,
 CVE-2018-5136, CVE-2018-5137, CVE-2018-5140, CVE-2018-5141, CVE-2018-5142)

 It was discovered that the fetch() API could incorrectly return cached
 copies of no-store/no-cache resources in some circumstances. A local
 attacker could potentially exploit this to obtain sensitive information in
 environments where multiple users share a common profile. (CVE-2018-5131)

 Multiple security issues were discovered with WebExtensions. If a user
 were tricked in to installing a specially crafted extension, an attacker
 could potentially exploit these to obtain sensitive information or bypass
 security restrictions. (CVE-2018-5132, CVE-2018-5134, CVE-2018-5135)

 It was discovered that the value of app.support.baseURL is not sanitized
 properly. If a malicious local application were to set this to a specially
 crafted value, an attacker could potentially exploit this to execute
 arbitrary code. (CVE-2018-5133)

 It was discovered that javascript: URLs with embedded tab characters could
 be pasted in to the addressbar. If a user were tricked in to copying a
 specially crafted URL in to the addressbar, an attacker could exploit this
 to conduct cross-site scripting (XSS) attacks. (CVE-2018-5143)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"59.0.2+build1-0ubuntu0.14.04.4", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"59.0.2+build1-0ubuntu0.16.04.3", rls:"UBUNTU16.04 LTS"))) {
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
