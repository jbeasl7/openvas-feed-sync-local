# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840647");
  script_cve_id("CVE-2010-1168", "CVE-2010-1447", "CVE-2010-2761", "CVE-2010-4410", "CVE-2010-4411", "CVE-2011-1487");
  script_tag(name:"creation_date", value:"2011-05-10 12:04:15 +0000 (Tue, 10 May 2011)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1129-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04|6\.06\ LTS|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-1129-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1129-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl' package(s) announced via the USN-1129-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the Safe.pm Perl module incorrectly handled
Safe::reval and Safe::rdo access restrictions. An attacker could use this
flaw to bypass intended restrictions and possibly execute arbitrary code.
(CVE-2010-1168, CVE-2010-1447)

It was discovered that the CGI.pm Perl module incorrectly handled certain
MIME boundary strings. An attacker could use this flaw to inject arbitrary
HTTP headers and perform HTTP response splitting and cross-site scripting
attacks. This issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 10.04 LTS and
10.10. (CVE-2010-2761, CVE-2010-4411)

It was discovered that the CGI.pm Perl module incorrectly handled newline
characters. An attacker could use this flaw to inject arbitrary HTTP
headers and perform HTTP response splitting and cross-site scripting
attacks. This issue only affected Ubuntu 6.06 LTS, 8.04 LTS, 10.04 LTS and
10.10. (CVE-2010-4410)

It was discovered that the lc, lcfirst, uc, and ucfirst functions did not
properly apply the taint attribute when processing tainted input. An
attacker could use this flaw to bypass intended restrictions. This issue
only affected Ubuntu 8.04 LTS, 10.04 LTS and 10.10. (CVE-2011-1487)");

  script_tag(name:"affected", value:"'perl' package(s) on Ubuntu 6.06, Ubuntu 8.04, Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"perl", ver:"5.10.1-8ubuntu2.1", rls:"UBUNTU10.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU10.10") {

  if(!isnull(res = isdpkgvuln(pkg:"perl", ver:"5.10.1-12ubuntu2.1", rls:"UBUNTU10.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU11.04") {

  if(!isnull(res = isdpkgvuln(pkg:"perl", ver:"5.10.1-17ubuntu4.1", rls:"UBUNTU11.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"perl", ver:"5.8.7-10ubuntu1.3", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU8.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"perl", ver:"5.8.8-12ubuntu0.5", rls:"UBUNTU8.04 LTS"))) {
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
