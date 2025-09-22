# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.842186");
  script_cve_id("CVE-2015-3143", "CVE-2015-3144", "CVE-2015-3145", "CVE-2015-3148", "CVE-2015-3153");
  script_tag(name:"creation_date", value:"2015-05-01 03:50:17 +0000 (Fri, 01 May 2015)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-2591-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS|14\.10|15\.04)");

  script_xref(name:"Advisory-ID", value:"USN-2591-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-2591-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the USN-2591-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Paras Sethia discovered that curl could incorrectly re-use NTLM HTTP
credentials when subsequently connecting to the same host over HTTP.
(CVE-2015-3143)

Hanno Bock discovered that curl incorrectly handled zero-length host names.
If a user or automated system were tricked into using a specially crafted
host name, an attacker could possibly use this issue to cause curl to
crash, resulting in a denial of service, or possibly execute arbitrary
code. This issue only affected Ubuntu 14.10 and Ubuntu 15.04.
(CVE-2015-3144)

Hanno Bock discovered that curl incorrectly handled cookie path elements.
If a user or automated system were tricked into parsing a specially crafted
cookie, an attacker could possibly use this issue to cause curl to crash,
resulting in a denial of service, or possibly execute arbitrary code. This
issue only affected Ubuntu 14.04 LTS, Ubuntu 14.10 and Ubuntu 15.04.
(CVE-2015-3145)

Isaac Boukris discovered that when using Negotiate authenticated
connections, curl could incorrectly authenticate the entire connection and
not just specific HTTP requests. (CVE-2015-3148)

Yehezkel Horowitz and Oren Souroujon discovered that curl sent HTTP headers
both to servers and proxies by default, contrary to expectations. This
issue only affected Ubuntu 14.10 and Ubuntu 15.04. (CVE-2015-3153)");

  script_tag(name:"affected", value:"'curl' package(s) on Ubuntu 12.04, Ubuntu 14.04, Ubuntu 14.10, Ubuntu 15.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.22.0-3ubuntu4.14", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.22.0-3ubuntu4.14", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.22.0-3ubuntu4.14", rls:"UBUNTU12.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.35.0-1ubuntu2.5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.35.0-1ubuntu2.5", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.35.0-1ubuntu2.5", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.37.1-1ubuntu3.4", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.37.1-1ubuntu3.4", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.37.1-1ubuntu3.4", rls:"UBUNTU14.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU15.04") {

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3", ver:"7.38.0-3ubuntu2.2", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-gnutls", ver:"7.38.0-3ubuntu2.2", rls:"UBUNTU15.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcurl3-nss", ver:"7.38.0-3ubuntu2.2", rls:"UBUNTU15.04"))) {
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
