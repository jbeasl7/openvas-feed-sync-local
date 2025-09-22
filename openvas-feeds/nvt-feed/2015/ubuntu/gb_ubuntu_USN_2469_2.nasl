# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842086");
  script_cve_id("CVE-2015-0219", "CVE-2015-0220", "CVE-2015-0221", "CVE-2015-0222");
  script_tag(name:"creation_date", value:"2015-02-05 05:06:18 +0000 (Thu, 05 Feb 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Ubuntu: Security Advisory (USN-2469-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|12\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-2469-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2469-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1417274");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-django' package(s) announced via the USN-2469-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-2469-1 fixed vulnerabilities in Django. The security fix for
CVE-2015-0221 introduced a regression on Ubuntu 10.04 LTS and Ubuntu 12.04
LTS when serving static content through GZipMiddleware. This update fixes
the problem.

We apologize for the inconvenience.

Original advisory details:

 Jedediah Smith discovered that Django incorrectly handled underscores in
 WSGI headers. A remote attacker could possibly use this issue to spoof
 headers in certain environments. (CVE-2015-0219)

 Mikko Ohtamaa discovered that Django incorrectly handled user-supplied
 redirect URLs. A remote attacker could possibly use this issue to perform a
 cross-site scripting attack. (CVE-2015-0220)

 Alex Gaynor discovered that Django incorrectly handled reading files in
 django.views.static.serve(). A remote attacker could possibly use this
 issue to cause Django to consume resources, resulting in a denial of
 service. (CVE-2015-0221)

 Keryn Knight discovered that Django incorrectly handled forms with
 ModelMultipleChoiceField. A remote attacker could possibly use this issue
 to cause a large number of SQL queries, resulting in a database denial of
 service. This issue only affected Ubuntu 14.04 LTS and Ubuntu 14.10.
 (CVE-2015-0222)");

  script_tag(name:"affected", value:"'python-django' package(s) on Ubuntu 10.04, Ubuntu 12.04.");

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

if(release == "UBUNTU10.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.1.1-2ubuntu1.16", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python-django", ver:"1.3.1-4ubuntu1.15", rls:"UBUNTU12.04 LTS"))) {
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
