# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63144");
  script_cve_id("CVE-2007-3074", "CVE-2008-0016", "CVE-2008-0017", "CVE-2008-0304", "CVE-2008-2785", "CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2811", "CVE-2008-2933", "CVE-2008-3835", "CVE-2008-3836", "CVE-2008-3837", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4065", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4069", "CVE-2008-4070", "CVE-2008-4582", "CVE-2008-5012", "CVE-2008-5013", "CVE-2008-5014", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5024", "CVE-2008-5052", "CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5511", "CVE-2008-5512");
  script_tag(name:"creation_date", value:"2009-01-13 21:38:32 +0000 (Tue, 13 Jan 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1697-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1697-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1697-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1697");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'iceape' package(s) announced via the DSA-1697-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Iceape an unbranded version of the Seamonkey internet suite. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0016

Justin Schuh, Tom Cross and Peter Williams discovered a buffer overflow in the parser for UTF-8 URLs, which may lead to the execution of arbitrary code. (MFSA 2008-37)

CVE-2008-0304

It was discovered that a buffer overflow in MIME decoding can lead to the execution of arbitrary code. (MFSA 2008-26)

CVE-2008-2785

It was discovered that missing boundary checks on a reference counter for CSS objects can lead to the execution of arbitrary code. (MFSA 2008-34)

CVE-2008-2798

Devon Hubbard, Jesse Ruderman and Martijn Wargers discovered crashes in the layout engine, which might allow the execution of arbitrary code. (MFSA 2008-21)

CVE-2008-2799

Igor Bukanov, Jesse Ruderman and Gary Kwong discovered crashes in the Javascript engine, which might allow the execution of arbitrary code. (MFSA 2008-21)

CVE-2008-2800

'moz_bug_r_a4' discovered several cross-site scripting vulnerabilities. (MFSA 2008-22)

CVE-2008-2801

Collin Jackson and Adam Barth discovered that Javascript code could be executed in the context or signed JAR archives. (MFSA 2008-23)

CVE-2008-2802

'moz_bug_r_a4' discovered that XUL documements can escalate privileges by accessing the pre-compiled 'fastload' file. (MFSA 2008-24)

CVE-2008-2803

'moz_bug_r_a4' discovered that missing input sanitising in the mozIJSSubScriptLoader.loadSubScript() function could lead to the execution of arbitrary code. Iceape itself is not affected, but some addons are. (MFSA 2008-25)

CVE-2008-2805

Claudio Santambrogio discovered that missing access validation in DOM parsing allows malicious web sites to force the browser to upload local files to the server, which could lead to information disclosure. (MFSA 2008-27)

CVE-2008-2807

Daniel Glazman discovered that a programming error in the code for parsing .properties files could lead to memory content being exposed to addons, which could lead to information disclosure. (MFSA 2008-29)

CVE-2008-2808

Masahiro Yamada discovered that file URLs in directory listings were insufficiently escaped. (MFSA 2008-30)

CVE-2008-2809

John G. Myers, Frank Benkstein and Nils Toedtmann discovered that alternate names on self-signed certificates were handled insufficiently, which could lead to spoofings of secure connections. (MFSA 2008-31)

CVE-2008-2810

It was discovered that URL shortcut files could be used to bypass the same-origin restrictions. This issue does not affect current Iceape, but might occur with additional extensions installed. (MFSA 2008-32)

CVE-2008-2811

Greg McManus discovered a crash in the block reflow code, which might allow the execution of arbitrary code. (MFSA 2008-33)

CVE-2008-2933

Billy Rios discovered that passing an URL containing a pipe symbol to ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'iceape' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"iceape", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-browser", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-calendar", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-chatzilla", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-dbg", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-dev", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-dom-inspector", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-gnome-support", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"iceape-mailnews", ver:"1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla", ver:"2:1.8+1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-browser", ver:"2:1.8+1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-calendar", ver:"2:1.8+1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-chatzilla", ver:"2:1.8+1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-dev", ver:"2:1.8+1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-dom-inspector", ver:"2:1.8+1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-js-debugger", ver:"2:1.8+1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-mailnews", ver:"2:1.8+1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-psm", ver:"2:1.8+1.0.13~pre080614i-0etch1", rls:"DEB4"))) {
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
