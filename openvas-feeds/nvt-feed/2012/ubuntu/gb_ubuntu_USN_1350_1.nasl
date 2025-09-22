# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840889");
  script_cve_id("CVE-2011-3659", "CVE-2011-3670", "CVE-2012-0442", "CVE-2012-0444", "CVE-2012-0449");
  script_tag(name:"creation_date", value:"2012-02-13 11:01:10 +0000 (Mon, 13 Feb 2012)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-1350-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(10\.04\ LTS|10\.10|11\.04)");

  script_xref(name:"Advisory-ID", value:"USN-1350-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-1350-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-1350-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jesse Ruderman and Bob Clary discovered memory safety issues affecting
Thunderbird. If the user were tricked into opening a specially crafted
page, an attacker could exploit these to cause a denial of service via
application crash, or potentially execute code with the privileges of the
user invoking Thunderbird. (CVE-2012-0442)

It was discovered that Thunderbird did not properly handle node removal in
the DOM. If the user were tricked into opening a specially crafted page, an
attacker could exploit this to cause a denial of service via application
crash, or potentially execute code with the privileges of the user invoking
Thunderbird. (CVE-2011-3659)

It was discovered that memory corruption could occur during the decoding of
Ogg Vorbis files. If the user were tricked into opening a specially crafted
file, an attacker could exploit this to cause a denial of service via
application crash, or potentially execute code with the privileges of the
user invoking Thunderbird. (CVE-2012-0444)

Nicolas Gregoire and Aki Helin discovered that when processing a malformed
embedded XSLT stylesheet, Thunderbird can crash due to memory corruption.
If the user were tricked into opening a specially crafted page, an attacker
could exploit this to cause a denial of service via application crash, or
potentially execute code with the privileges of the user invoking
Thunderbird. (CVE-2012-0449)

Gregory Fleischer discovered that requests using IPv6 hostname syntax
through certain proxies might generate errors. An attacker might be able to
use this to read sensitive data from the error messages. (CVE-2011-3670)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 10.04, Ubuntu 10.10, Ubuntu 11.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"3.1.18+build2+nobinonly-0ubuntu0.10.04.1", rls:"UBUNTU10.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"3.1.18+build2+nobinonly-0ubuntu0.10.10.1", rls:"UBUNTU10.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"3.1.18+build2+nobinonly-0ubuntu0.11.04.1", rls:"UBUNTU11.04"))) {
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
