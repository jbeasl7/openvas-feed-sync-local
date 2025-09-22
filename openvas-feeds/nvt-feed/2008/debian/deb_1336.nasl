# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58468");
  script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0045", "CVE-2007-0775", "CVE-2007-0778", "CVE-2007-0981", "CVE-2007-0994", "CVE-2007-0995", "CVE-2007-0996", "CVE-2007-1282");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1336-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1336-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1336-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1336");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mozilla-firefox' package(s) announced via the DSA-1336-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Mozilla Firefox.

This will be the last security update of Mozilla-based products for the oldstable (sarge) distribution of Debian. We recommend to upgrade to stable (etch) as soon as possible.

The Common Vulnerabilities and Exposures project identifies the following vulnerabilities:

CVE-2007-1282

It was discovered that an integer overflow in text/enhanced message parsing allows the execution of arbitrary code.

CVE-2007-0994

It was discovered that a regression in the Javascript engine allows the execution of Javascript with elevated privileges.

CVE-2007-0995

It was discovered that incorrect parsing of invalid HTML characters allows the bypass of content filters.

CVE-2007-0996

It was discovered that insecure child frame handling allows cross-site scripting.

CVE-2007-0981

It was discovered that Firefox handles URI with a null byte in the hostname insecurely.

CVE-2007-0008

It was discovered that a buffer overflow in the NSS code allows the execution of arbitrary code.

CVE-2007-0009

It was discovered that a buffer overflow in the NSS code allows the execution of arbitrary code.

CVE-2007-0775

It was discovered that multiple programming errors in the layout engine allow the execution of arbitrary code.

CVE-2007-0778

It was discovered that the page cache calculates hashes in an insecure manner.

CVE-2006-6077

It was discovered that the password manager allows the disclosure of passwords.

For the oldstable distribution (sarge) these problems have been fixed in version 1.0.4-2sarge17. You should upgrade to etch as soon as possible.

The stable distribution (etch) isn't affected. These vulnerabilities have been fixed prior to the release of Debian etch.

The unstable distribution (sid) no longer contains mozilla-firefox. Iceweasel is already fixed.");

  script_tag(name:"affected", value:"'mozilla-firefox' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox", ver:"1.0.4-2sarge17", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-dom-inspector", ver:"1.0.4-2sarge17", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-firefox-gnome-support", ver:"1.0.4-2sarge17", rls:"DEB3.1"))) {
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
