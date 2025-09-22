# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58355");
  script_cve_id("CVE-2007-1558", "CVE-2007-2867", "CVE-2007-2868");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1305-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1305-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1305-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1305");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'icedove' package(s) announced via the DSA-1305-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in the Icedove mail client, an unbranded version of the Thunderbird client. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1558

Gatan Leurent discovered a cryptographical weakness in APOP authentication, which reduces the required efforts for an MITM attack to intercept a password. The update enforces stricter validation, which prevents this attack.

CVE-2007-2867

Boris Zbarsky, Eli Friedman, Georgi Guninski, Jesse Ruderman, Martijn Wargers and Olli Pettay discovered crashes in the layout engine, which might allow the execution of arbitrary code.

CVE-2007-2868

Brendan Eich, Igor Bukanov, Jesse Ruderman, moz_bug_r_a4 and Wladimir Palant discovered crashes in the Javascript engine, which might allow the execution of arbitrary code. Generally, enabling Javascript in Icedove is not recommended.

Fixes for the oldstable distribution (sarge) are not available. While there will be another round of security updates for Mozilla products, Debian doesn't have the resources to backport further security fixes to the old Mozilla products. You're strongly encouraged to upgrade to stable as soon as possible.

For the stable distribution (etch) these problems have been fixed in version 1.5.0.12.dfsg1-0etch1.

The unstable distribution (sid) will be fixed soon.

We recommend that you upgrade your icedove packages.");

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

  if(!isnull(res = isdpkgvuln(pkg:"icedove", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dbg", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-dev", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-gnome-support", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-inspector", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"icedove-typeaheadfind", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-dev", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-inspector", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird-typeaheadfind", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-dbg", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-dev", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-gnome-support", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-inspector", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird-typeaheadfind", ver:"1.5.0.12.dfsg1-0etch1", rls:"DEB4"))) {
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
