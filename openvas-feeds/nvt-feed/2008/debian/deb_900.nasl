# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55908");
  script_cve_id("CVE-2005-3088");
  script_tag(name:"creation_date", value:"2008-01-17 22:07:13 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-900-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.0|3\.1)");

  script_xref(name:"Advisory-ID", value:"DSA-900-3");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-900-3");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-900");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fetchmail, fetchmail-ssl' package(s) announced via the DSA-900-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Due to restrictive dependency definition for fetchmail-ssl the updated fetchmailconf package couldn't be installed on the old stable distribution (woody) together with fetchmail-ssl. Hence, this update loosens it, so that the update can be pulled in. For completeness we're including the original advisory text:

Thomas Wolff discovered that the fetchmailconf program which is provided as part of fetchmail, an SSL enabled POP3, APOP, IMAP mail gatherer/forwarder, creates the new configuration in an insecure fashion that can lead to leaking passwords for mail accounts to local users.

This update also fixes a regression in the package for stable caused by the last security update.

For the old stable distribution (woody) this problem has been fixed in version 5.9.11-6.4 of fetchmail and in version 5.9.11-6.3 of fetchmail-ssl.

For the stable distribution (sarge) this problem has been fixed in version 6.2.5-12sarge3.

For the unstable distribution (sid) this problem has been fixed in version 6.2.5.4-1.

We recommend that you upgrade your fetchmail package.");

  script_tag(name:"affected", value:"'fetchmail, fetchmail-ssl' package(s) on Debian 3.0, Debian 3.1.");

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

if(release == "DEB3.0") {

  if(!isnull(res = isdpkgvuln(pkg:"fetchmail", ver:"5.9.11-6.4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fetchmail-common", ver:"5.9.11-6.4", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fetchmail-ssl", ver:"5.9.11-6.3", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fetchmailconf", ver:"5.9.11-6.4", rls:"DEB3.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB3.1") {

  if(!isnull(res = isdpkgvuln(pkg:"fetchmail", ver:"6.2.5-12sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fetchmail-ssl", ver:"6.2.5-12sarge3", rls:"DEB3.1"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fetchmailconf", ver:"6.2.5-12sarge3", rls:"DEB3.1"))) {
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
