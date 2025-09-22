# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.62955");
  script_cve_id("CVE-2008-5005", "CVE-2008-5006");
  script_tag(name:"creation_date", value:"2008-12-23 17:28:16 +0000 (Tue, 23 Dec 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1685-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1685-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1685-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1685");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'uw-imap' package(s) announced via the DSA-1685-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been found in uw-imap, an IMAP implementation. The Common Vulnerabilities and Exposures project identifies the following problems:

It was discovered that several buffer overflows can be triggered via a long folder extension argument to the tmail or dmail program. This could lead to arbitrary code execution (CVE-2008-5005).

It was discovered that a NULL pointer dereference could be triggered by a malicious response to the QUIT command leading to a denial of service (CVE-2008-5006).

For the stable distribution (etch), these problems have been fixed in version 2002edebian1-13.1+etch1.

For the unstable distribution (sid) and the testing distribution (lenny), these problems have been fixed in version 2007d~dfsg-1.

We recommend that you upgrade your uw-imap packages.");

  script_tag(name:"affected", value:"'uw-imap' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ipopd", ver:"7:2002edebian1-13.1+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipopd-ssl", ver:"7:2002edebian1-13.1+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc-client-dev", ver:"7:2002edebian1-13.1+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libc-client2002edebian", ver:"7:2002edebian1-13.1+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mlock", ver:"7:2002edebian1-13.1+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uw-imapd", ver:"7:2002edebian1-13.1+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uw-imapd-ssl", ver:"7:2002edebian1-13.1+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uw-mailutils", ver:"7:2002edebian1-13.1+etch1", rls:"DEB4"))) {
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
