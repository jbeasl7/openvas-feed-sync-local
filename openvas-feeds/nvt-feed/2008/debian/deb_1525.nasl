# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60616");
  script_cve_id("CVE-2007-6430", "CVE-2008-1332", "CVE-2008-1333");
  script_tag(name:"creation_date", value:"2008-03-27 17:25:13 +0000 (Thu, 27 Mar 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:N");

  script_name("Debian: Security Advisory (DSA-1525-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1525-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1525-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1525");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'asterisk' package(s) announced via the DSA-1525-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Asterisk, a free software PBX and telephony toolkit. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-6430

Tilghman Lesher discovered that database-based registrations are insufficiently validated. This only affects setups, which are configured to run without a password and only host-based authentication.

CVE-2008-1332

Jason Parker discovered that insufficient validation of From: headers inside the SIP channel driver may lead to authentication bypass and the potential external initiation of calls.

CVE-2008-1333

This update also fixes a format string vulnerability, which can only be triggered through configuration files under control of the local administrator. In later releases of Asterisk this issue is remotely exploitable and tracked as CVE-2008-1333.

The status of the old stable distribution (sarge) is currently being investigated. If affected, an update will be released through security.debian.org.

For the stable distribution (etch), these problems have been fixed in version 1:1.2.13~dfsg-2etch3.

We recommend that you upgrade your asterisk packages.");

  script_tag(name:"affected", value:"'asterisk' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"asterisk", ver:"1:1.2.13~dfsg-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-bristuff", ver:"1:1.2.13~dfsg-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-classic", ver:"1:1.2.13~dfsg-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-config", ver:"1:1.2.13~dfsg-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-dev", ver:"1:1.2.13~dfsg-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-doc", ver:"1:1.2.13~dfsg-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-h323", ver:"1:1.2.13~dfsg-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-sounds-main", ver:"1:1.2.13~dfsg-2etch3", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"asterisk-web-vmail", ver:"1:1.2.13~dfsg-2etch3", rls:"DEB4"))) {
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
