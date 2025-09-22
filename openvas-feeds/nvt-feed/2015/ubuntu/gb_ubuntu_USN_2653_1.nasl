# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842261");
  script_cve_id("CVE-2013-1752", "CVE-2013-1753", "CVE-2014-4616", "CVE-2014-4650", "CVE-2014-7185");
  script_tag(name:"creation_date", value:"2015-06-26 04:25:01 +0000 (Fri, 26 Jun 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-26 13:49:27 +0000 (Wed, 26 Feb 2020)");

  script_name("Ubuntu: Security Advisory (USN-2653-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|14\.10)");

  script_xref(name:"Advisory-ID", value:"USN-2653-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2653-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7, python3.2, python3.4' package(s) announced via the USN-2653-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that multiple Python protocol libraries incorrectly
limited certain data when connecting to servers. A malicious ftp, http,
imap, nntp, pop or smtp server could use this issue to cause a denial of
service. (CVE-2013-1752)

It was discovered that the Python xmlrpc library did not limit unpacking
gzip-compressed HTTP bodies. A malicious server could use this issue to
cause a denial of service. (CVE-2013-1753)

It was discovered that the Python json module incorrectly handled a certain
argument. An attacker could possibly use this issue to read arbitrary
memory and expose sensitive information. This issue only affected Ubuntu
12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-4616)

It was discovered that the Python CGIHTTPServer incorrectly handled
URL-encoded path separators in URLs. A remote attacker could use this issue
to expose sensitive information, or possibly execute arbitrary code. This
issue only affected Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-4650)

It was discovered that Python incorrectly handled sizes and offsets in
buffer functions. An attacker could possibly use this issue to read
arbitrary memory and obtain sensitive information. This issue only affected
Ubuntu 12.04 LTS and Ubuntu 14.04 LTS. (CVE-2014-7185)");

  script_tag(name:"affected", value:"'python2.7, python3.2, python3.4' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.3-0ubuntu3.8", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.3-0ubuntu3.8", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.2", ver:"3.2.3-0ubuntu3.7", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.2-minimal", ver:"3.2.3-0ubuntu3.7", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.6-8ubuntu0.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.6-8ubuntu0.2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.4", ver:"3.4.0-2ubuntu1.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.4-minimal", ver:"3.4.0-2ubuntu1.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.10") {

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.8-10ubuntu1.1", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.8-10ubuntu1.1", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.4", ver:"3.4.2-1ubuntu0.1", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.4-minimal", ver:"3.4.2-1ubuntu0.1", rls:"UBUNTU14.10"))) {
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
