# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63143");
  script_cve_id("CVE-2008-0016", "CVE-2008-1380", "CVE-2008-3835", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4065", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4070", "CVE-2008-4582", "CVE-2008-5012", "CVE-2008-5014", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5024", "CVE-2008-5052", "CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5511", "CVE-2008-5512");
  script_tag(name:"creation_date", value:"2009-01-13 21:38:32 +0000 (Tue, 13 Jan 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1696-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1696-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1696-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1696");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-1696-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Icedove mail client, an unbranded version of the Thunderbird mail client. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0016

Justin Schuh, Tom Cross and Peter Williams discovered a buffer overflow in the parser for UTF-8 URLs, which may lead to the execution of arbitrary code. (MFSA 2008-37)

CVE-2008-1380

It was discovered that crashes in the Javascript engine could potentially lead to the execution of arbitrary code. (MFSA 2008-20)

CVE-2008-3835

'moz_bug_r_a4' discovered that the same-origin check in nsXMLDocument::OnChannelRedirect() could be bypassed. (MFSA 2008-38)

CVE-2008-4058

'moz_bug_r_a4' discovered a vulnerability which can result in Chrome privilege escalation through XPCNativeWrappers. (MFSA 2008-41)

CVE-2008-4059

'moz_bug_r_a4' discovered a vulnerability which can result in Chrome privilege escalation through XPCNativeWrappers. (MFSA 2008-41)

CVE-2008-4060

Olli Pettay and 'moz_bug_r_a4' discovered a Chrome privilege escalation vulnerability in XSLT handling. (MFSA 2008-41)

CVE-2008-4061

Jesse Ruderman discovered a crash in the layout engine, which might allow the execution of arbitrary code. (MFSA 2008-42)

CVE-2008-4062

Igor Bukanov, Philip Taylor, Georgi Guninski and Antoine Labour discovered crashes in the Javascript engine, which might allow the execution of arbitrary code. (MFSA 2008-42)

CVE-2008-4065

Dave Reed discovered that some Unicode byte order marks are stripped from Javascript code before execution, which can result in code being executed, which were otherwise part of a quoted string. (MFSA 2008-43)

CVE-2008-4067

It was discovered that a directory traversal allows attackers to read arbitrary files via a certain character. (MFSA 2008-44)

CVE-2008-4068

It was discovered that a directory traversal allows attackers to bypass security restrictions and obtain sensitive information. (MFSA 2008-44)

CVE-2008-4070

It was discovered that a buffer overflow could be triggered via a long header in a news article, which could lead to arbitrary code execution. (MFSA 2008-46)

CVE-2008-4582

Liu Die Yu and Boris Zbarsky discovered an information leak through local shortcut files. (MFSA 2008-47, MFSA 2008-59)

CVE-2008-5012

Georgi Guninski, Michal Zalewski and Chris Evan discovered that the canvas element could be used to bypass same-origin restrictions. (MFSA 2008-48)

CVE-2008-5014

Jesse Ruderman discovered that a programming error in the window.__proto__.__proto__ object could lead to arbitrary code execution. (MFSA 2008-50)

CVE-2008-5017

It was discovered that crashes in the layout engine could lead to arbitrary code execution. (MFSA 2008-52)

CVE-2008-5018

It was discovered that crashes in the Javascript engine could lead to arbitrary code execution. (MFSA 2008-52)

CVE-2008-5021

It was discovered that a crash in the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'icedove' package(s) on Debian 4.");

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

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"icedove", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dbg", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dev", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-gnome-support", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-inspector", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-typeaheadfind", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-dbg", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-dev", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-inspector", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-typeaheadfind", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614i-0etch1", rls:"DEB4"))) {
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
