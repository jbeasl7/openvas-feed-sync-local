# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.840192");
  script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0416", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0420", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");
  script_tag(name:"creation_date", value:"2009-03-23 09:59:50 +0000 (Mon, 23 Mar 2009)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-576-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(6\.06\ LTS|6\.10|7\.04|7\.10)");

  script_xref(name:"Advisory-ID", value:"USN-576-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-576-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-576-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Various flaws were discovered in the browser and JavaScript engine.
By tricking a user into opening a malicious web page, an attacker
could execute arbitrary code with the user's privileges.
(CVE-2008-0412, CVE-2008-0413)

Flaws were discovered in the file upload form control. A malicious
website could force arbitrary files from the user's computer to be
uploaded without consent. (CVE-2008-0414)

Various flaws were discovered in the JavaScript engine. By tricking
a user into opening a malicious web page, an attacker could escalate
privileges within the browser, perform cross-site scripting attacks
and/or execute arbitrary code with the user's privileges. (CVE-2008-0415)

Various flaws were discovered in character encoding handling. If a
user were ticked into opening a malicious web page, an attacker
could perform cross-site scripting attacks. (CVE-2008-0416)

Justin Dolske discovered a flaw in the password saving mechanism. By
tricking a user into opening a malicious web page, an attacker could
corrupt the user's stored passwords. (CVE-2008-0417)

Gerry Eisenhaur discovered that the chrome URI scheme did not properly
guard against directory traversal. Under certain circumstances, an
attacker may be able to load files or steal session data. Ubuntu is
not vulnerable in the default installation. (CVE-2008-0418)

David Bloom discovered flaws in the way images are treated by the
browser. A malicious website could exploit this to steal the user's
history information, crash the browser and/or possibly execute
arbitrary code with the user's privileges. (CVE-2008-0419)

Flaws were discovered in the BMP decoder. By tricking a user into
opening a specially crafted BMP file, an attacker could obtain
sensitive information. (CVE-2008-0420)

Michal Zalewski discovered flaws with timer-enabled security dialogs.
A malicious website could force the user to confirm a security dialog
without explicit consent. (CVE-2008-0591)

It was discovered that Firefox mishandled locally saved plain text
files. By tricking a user into saving a specially crafted text file,
an attacker could prevent the browser from displaying local files
with a .txt extension. (CVE-2008-0592)

Martin Straka discovered flaws in stylesheet handling after a 302
redirect. By tricking a user into opening a malicious web page, an
attacker could obtain sensitive URL parameters. (CVE-2008-0593)

Emil Ljungdahl and Lars-Olof Moilanen discovered that a web forgery
warning dialog wasn't displayed under certain circumstances. A
malicious website could exploit this to conduct phishing attacks
against the user. (CVE-2008-0594)");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"1.5.dfsg+1.5.0.15~prepatch080202a-0ubuntu1", rls:"UBUNTU6.06 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.12+0nobinonly+2-0ubuntu0.6.10", rls:"UBUNTU6.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.12+1nobinonly+2-0ubuntu0.7.4", rls:"UBUNTU7.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"2.0.0.12+2nobinonly+2-0ubuntu0.7.10", rls:"UBUNTU7.10"))) {
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
