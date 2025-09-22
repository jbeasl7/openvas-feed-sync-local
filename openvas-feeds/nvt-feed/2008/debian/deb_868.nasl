# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55711");
  script_cve_id("CVE-2005-2701", "CVE-2005-2702", "CVE-2005-2703", "CVE-2005-2704", "CVE-2005-2705", "CVE-2005-2706", "CVE-2005-2707", "CVE-2005-2871", "CVE-2005-2968");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-868-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-868-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-868-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-868");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mozilla-thunderbird' package(s) announced via the DSA-868-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security-related problems have been discovered in Mozilla and derived programs. Some of the following problems don't exactly apply to Mozilla Thunderbird, even though the code is present. In order to keep the codebase in sync with upstream it has been altered nevertheless. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-2871

Tom Ferris discovered a bug in the IDN hostname handling of Mozilla that allows remote attackers to cause a denial of service and possibly execute arbitrary code via a hostname with dashes.

CAN-2005-2701

A buffer overflow allows remote attackers to execute arbitrary code via an XBM image file that ends in a large number of spaces instead of the expected end tag.

CAN-2005-2702

Mats Palmgren discovered a buffer overflow in the Unicode string parser that allows a specially crafted Unicode sequence to overflow a buffer and cause arbitrary code to be executed.

CAN-2005-2703

Remote attackers could spoof HTTP headers of XML HTTP requests via XMLHttpRequest and possibly use the client to exploit vulnerabilities in servers or proxies.

CAN-2005-2704

Remote attackers could spoof DOM objects via an XBL control that implements an internal XPCOM interface.

CAN-2005-2705

Georgi Guninski discovered an integer overflow in the JavaScript engine that might allow remote attackers to execute arbitrary code.

CAN-2005-2706

Remote attackers could execute Javascript code with chrome privileges via an about: page such as about:mozilla.

CAN-2005-2707

Remote attackers could spawn windows without user interface components such as the address and status bar that could be used to conduct spoofing or phishing attacks.

CAN-2005-2968

Peter Zelezny discovered that shell metacharacters are not properly escaped when they are passed to a shell script and allow the execution of arbitrary commands, e.g. when a malicious URL is automatically copied from another program into Mozilla as default browser.

For the stable distribution (sarge) these problems have been fixed in version 1.0.2-2.sarge1.0.7.

For the unstable distribution (sid) these problems have been fixed in version 1.0.7-1.

We recommend that you upgrade your mozilla-thunderbird package.");

  script_tag(name:"affected", value:"'mozilla-thunderbird' package(s) on Debian 3.1.");

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

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.0.2-2.sarge1.0.7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.0.2-2.sarge1.0.7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.0.2-2.sarge1.0.7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-offline", ver:"1.0.2-2.sarge1.0.7", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.0.2-2.sarge1.0.7", rls:"DEB3.1"))) {
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
