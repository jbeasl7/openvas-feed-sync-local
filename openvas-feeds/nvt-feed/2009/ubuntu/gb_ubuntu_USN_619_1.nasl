# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840250");
  script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2806", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2810", "CVE-2008-2811");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-619-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|7\.04|7\.10)");

  script_xref(name:"Advisory-ID", value:"USN-619-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-619-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-619-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various flaws were discovered in the browser engine. By tricking
a user into opening a malicious web page, an attacker could cause
a denial of service via application crash, or possibly execute
arbitrary code with the privileges of the user invoking the
program. (CVE-2008-2798, CVE-2008-2799)

Several problems were discovered in the JavaScript engine. If a
user were tricked into opening a malicious web page, an attacker
could perform cross-site scripting attacks. (CVE-2008-2800)

Collin Jackson discovered various flaws in the JavaScript engine
which allowed JavaScript to be injected into signed JAR files. If
a user were tricked into opening malicious web content, an
attacker may be able to execute arbitrary code with the privileges
of a different website or link content within the JAR file to an
attacker-controlled JavaScript file. (CVE-2008-2801)

It was discovered that Firefox would allow non-privileged XUL
documents to load chrome scripts from the fastload file. This
could allow an attacker to execute arbitrary JavaScript code with
chrome privileges. (CVE-2008-2802)

A flaw was discovered in Firefox that allowed overwriting trusted
objects via mozIJSSubScriptLoader.loadSubScript(). If a user were
tricked into opening a malicious web page, an attacker could
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2008-2803)

Claudio Santambrogio discovered a vulnerability in Firefox which
could lead to stealing of arbitrary files. If a user were tricked
into opening malicious content, an attacker could force the browser
into uploading local files to the remote server. (CVE-2008-2805)

Gregory Fleischer discovered a flaw in Java LiveConnect. An attacker
could exploit this to bypass the same-origin policy and create
arbitrary socket connections to other domains. (CVE-2008-2806)

Daniel Glazman found that an improperly encoded .properties file
in an add-on can result in uninitialized memory being used. If
a user were tricked into installing a malicious add-on, the
browser may be able to see data from other programs.
(CVE-2008-2807)

Masahiro Yamada discovered that Firefox did not properly sanitize
file URLs in directory listings, resulting in files from directory
listings being opened in unintended ways or not being able to be
opened by the browser at all. (CVE-2008-2808)

John G. Myers discovered a weakness in the trust model used by
Firefox regarding alternate names on self-signed certificates. If
a user were tricked into accepting a certificate containing
alternate name entries, an attacker could impersonate another
server. (CVE-2008-2809)

A flaw was discovered in the way Firefox opened URL files. If a user
were tricked into opening a bookmark to a malicious web page, the
page could potentially read from local files on the user's computer.
(CVE-2008-2810)

A vulnerability was discovered in the block reflow code of Firefox.
This vulnerability ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 6.06, Ubuntu 7.04, Ubuntu 7.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"1.5.dfsg+1.5.0.15~prepatch080614c-0ubuntu1", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.15+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.15+1nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10"))) {
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
