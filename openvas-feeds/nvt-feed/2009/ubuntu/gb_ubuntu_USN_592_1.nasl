# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840285");
  script_cve_id("CVE-2007-4879", "CVE-2008-0416", "CVE-2008-1195", "CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1240", "CVE-2008-1241");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-592-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|6\.10|7\.04|7\.10)");

  script_xref(name:"Advisory-ID", value:"USN-592-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-592-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-592-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Alexey Proskuryakov, Yosuke Hasegawa and Simon Montagu discovered flaws
in Firefox's character encoding handling. If a user were tricked into
opening a malicious web page, an attacker could perform cross-site
scripting attacks. (CVE-2008-0416)

Various flaws were discovered in the JavaScript engine. By tricking
a user into opening a malicious web page, an attacker could escalate
privileges within the browser, perform cross-site scripting attacks
and/or execute arbitrary code with the user's privileges.
(CVE-2008-1233, CVE-2008-1234, CVE-2008-1235)

Several problems were discovered in Firefox which could lead to crashes
and memory corruption. If a user were tricked into opening a malicious
web page, an attacker may be able to execute arbitrary code with the
user's privileges. (CVE-2008-1236, CVE-2008-1237)

Gregory Fleischer discovered Firefox did not properly process HTTP
Referrer headers when they were sent with requests to URLs
containing Basic Authentication credentials with empty usernames. An
attacker could exploit this vulnerability to perform cross-site request
forgery attacks. (CVE-2008-1238)

Peter Brodersen and Alexander Klink reported that default the setting in
Firefox for SSL Client Authentication allowed for users to be tracked
via their client certificate. The default has been changed to prompt
the user each time a website requests a client certificate.
(CVE-2007-4879)

Gregory Fleischer discovered that web content fetched via the jar
protocol could use Java LiveConnect to connect to arbitrary ports on
the user's machine due to improper parsing in the Java plugin. If a
user were tricked into opening malicious web content, an attacker may be
able to access services running on the user's machine. (CVE-2008-1195,
CVE-2008-1240)

Chris Thomas discovered that Firefox would allow an XUL popup from an
unselected tab to display in front of the selected tab. An attacker
could exploit this behavior to spoof a login prompt and steal the user's
credentials. (CVE-2008-1241)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 6.06, Ubuntu 6.10, Ubuntu 7.04, Ubuntu 7.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"1.5.dfsg+1.5.0.15~prepatch080323a-0ubuntu1", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.13+0nobinonly-0ubuntu0.6.10", rls:"UBUNTU6.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.13+0nobinonly-0ubuntu0.7.4", rls:"UBUNTU7.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.13+1nobinonly-0ubuntu0.7.10", rls:"UBUNTU7.10"))) {
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
