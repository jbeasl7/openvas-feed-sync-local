# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840295");
  script_cve_id("CVE-2008-2785", "CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2807", "CVE-2008-2809", "CVE-2008-2811");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-28T14:37:42+0000");
  script_tag(name:"last_modification", value:"2024-02-28 14:37:42 +0000 (Wed, 28 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-629-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|7\.04|7\.10|8\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-629-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-629-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-thunderbird, thunderbird' package(s) announced via the USN-629-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various flaws were discovered in the browser engine. If a user had
Javascript enabled and were tricked into opening a malicious web
page, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2008-2798, CVE-2008-2799)

It was discovered that Thunderbird would allow non-privileged XUL
documents to load chrome scripts from the fastload file if Javascript
was enabled. This could allow an attacker to execute arbitrary
Javascript code with chrome privileges. (CVE-2008-2802)

A flaw was discovered in Thunderbird that allowed overwriting trusted
objects via mozIJSSubScriptLoader.loadSubScript(). If a user had
Javascript enabled and was tricked into opening a malicious web page,
an attacker could execute arbitrary code with the privileges of the
user invoking the program. (CVE-2008-2803)

Daniel Glazman found that an improperly encoded .properties file in
an add-on can result in uninitialized memory being used. If a user
were tricked into installing a malicious add-on, Thunderbird may be
able to see data from other programs. (CVE-2008-2807)

John G. Myers discovered a weakness in the trust model used by
Thunderbird regarding alternate names on self-signed certificates.
If a user were tricked into accepting a certificate containing
alternate name entries, an attacker could impersonate another
server. (CVE-2008-2809)

A vulnerability was discovered in the block reflow code of
Thunderbird. If a user enabled Javascript, this vulnerability could
be used by an attacker to cause a denial of service via application
crash, or execute arbitrary code with the privileges of the user
invoking the program. (CVE-2008-2811)

A flaw was discovered in the browser engine. A variable could be made
to overflow causing Thunderbird to crash. If a user enable Javascript
and was tricked into opening a malicious web page, an attacker could
cause a denial of service or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2008-2785)

Mozilla developers audited the MIME handling code looking for similar
vulnerabilities to the previously fixed CVE-2008-0304, and changed
several function calls to use safer versions of string routines.");

  script_tag(name:"affected", value:"'mozilla-thunderbird, thunderbird' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10, Ubuntu 8.04.");

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

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.15~prepatch080614d-0ubuntu0.6.06.1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.04") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.15~prepatch080614d-0ubuntu0.7.04.1", rls:"UBUNTU7.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU7.10") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"2.0.0.16+nobinonly-0ubuntu0.7.10.1", rls:"UBUNTU7.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"2.0.0.16+nobinonly-0ubuntu0.8.04.1", rls:"UBUNTU8.04 LTS"))) {
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
