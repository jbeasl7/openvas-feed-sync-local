# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61373");
  script_cve_id("CVE-2008-0304", "CVE-2008-2785", "CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2807", "CVE-2008-2809", "CVE-2008-2811");
  script_tag(name:"creation_date", value:"2008-08-15 13:52:52 +0000 (Fri, 15 Aug 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1621-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1621-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1621-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1621");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-1621-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Icedove mail client, an unbranded version of the Thunderbird client. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2008-0304

It was discovered that a buffer overflow in MIME decoding can lead to the execution of arbitrary code.

CVE-2008-2785

It was discovered that missing boundary checks on a reference counter for CSS objects can lead to the execution of arbitrary code.

CVE-2008-2798

Devon Hubbard, Jesse Ruderman and Martijn Wargers discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2008-2799

Igor Bukanov, Jesse Ruderman and Gary Kwong discovered crashes in the Javascript engine, which might allow the execution of arbitrary code.

CVE-2008-2802

'moz_bug_r_a4' discovered that XUL documents can escalate privileges by accessing the pre-compiled 'fastload' file.

CVE-2008-2803

'moz_bug_r_a4' discovered that missing input sanitising in the mozIJSSubScriptLoader.loadSubScript() function could lead to the execution of arbitrary code. Iceweasel itself is not affected, but some addons are.

CVE-2008-2807

Daniel Glazman discovered that a programming error in the code for parsing .properties files could lead to memory content being exposed to addons, which could lead to information disclosure.

CVE-2008-2809

John G. Myers, Frank Benkstein and Nils Toedtmann discovered that alternate names on self-signed certificates were handled insufficiently, which could lead to spoofings secure connections.

CVE-2008-2811

Greg McManus discovered discovered a crash in the block reflow code, which might allow the execution of arbitrary code.

For the stable distribution (etch), these problems have been fixed in version 1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1. Packages for s390 are not yet available and will be provided later.

For the unstable distribution (sid), these problems have been fixed in version 2.0.0.16-1.

We recommend that you upgrade your icedove package.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedove", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dbg", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dev", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-gnome-support", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-inspector", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-typeaheadfind", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-dbg", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-dev", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-inspector", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-typeaheadfind", ver:"1.5.0.13+1.5.0.15b.dfsg1+prepatch080614d-0etch1", rls:"DEB4"))) {
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
