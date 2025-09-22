# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.61435");
  script_cve_id("CVE-2008-2936");
  script_tag(name:"creation_date", value:"2008-09-04 15:00:42 +0000 (Thu, 04 Sep 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1629-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1629-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1629-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1629");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'postfix' package(s) announced via the DSA-1629-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Sebastian Krahmer discovered that Postfix, a mail transfer agent, incorrectly checks the ownership of a mailbox. In some configurations, this allows for appending data to arbitrary files as root.

Note that only specific configurations are vulnerable, the default Debian installation is not affected. Only a configuration meeting the following requirements is vulnerable:

The mail delivery style is mailbox, with the Postfix built-in local(8) or virtual(8) delivery agents.

The mail spool directory (/var/spool/mail) is user-writeable.

The user can create hardlinks pointing to root-owned symlinks located in other directories.

For a detailed treating of the issue, please refer to the upstream author's announcement.

For the stable distribution (etch), this problem has been fixed in version 2.3.8-2+etch1.

For the testing distribution (lenny), this problem has been fixed in version 2.5.2-2lenny1.

For the unstable distribution (sid), this problem has been fixed in version 2.5.4-1.

We recommend that you upgrade your postfix package.");

  script_tag(name:"affected", value:"'postfix' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"postfix", ver:"2.3.8-2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postfix-cdb", ver:"2.3.8-2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postfix-dev", ver:"2.3.8-2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postfix-doc", ver:"2.3.8-2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postfix-ldap", ver:"2.3.8-2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postfix-mysql", ver:"2.3.8-2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postfix-pcre", ver:"2.3.8-2+etch1", rls:"DEB4"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"postfix-pgsql", ver:"2.3.8-2+etch1", rls:"DEB4"))) {
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
