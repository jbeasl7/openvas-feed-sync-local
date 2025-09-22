# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.54411");
  script_cve_id("CVE-2005-1524", "CVE-2005-1525", "CVE-2005-1526", "CVE-2005-2148", "CVE-2005-2149");
  script_tag(name:"creation_date", value:"2008-01-17 22:00:53 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-764-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.0|3\.1)");

  script_xref(name:"Advisory-ID", value:"DSA-764-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-764-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-764");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cacti' package(s) announced via the DSA-764-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in cacti, a round-robin database (RRD) tool that helps create graphs from database information. The Common Vulnerabilities and Exposures Project identifies the following problems:

CAN-2005-1524

Maciej Piotr Falkiewicz and an anonymous researcher discovered an input validation bug that allows an attacker to include arbitrary PHP code from remote sites which will allow the execution of arbitrary code on the server running cacti.

CAN-2005-1525

Due to missing input validation cacti allows a remote attacker to insert arbitrary SQL statements.

CAN-2005-1526

Maciej Piotr Falkiewicz discovered an input validation bug that allows an attacker to include arbitrary PHP code from remote sites which will allow the execution of arbitrary code on the server running cacti.

CAN-2005-2148

Stefan Esser discovered that the update for the above mentioned vulnerabilities does not perform proper input validation to protect against common attacks.

CAN-2005-2149

Stefan Esser discovered that the update for CAN-2005-1525 allows remote attackers to modify session information to gain privileges and disable the use of addslashes to protect against SQL injection.

For the old stable distribution (woody) these problems have been fixed in version 0.6.7-2.5.

For the stable distribution (sarge) these problems have been fixed in version 0.8.6c-7sarge2.

For the unstable distribution (sid) these problems have been fixed in version 0.8.6f-2.

We recommend that you upgrade your cacti package.");

  script_tag(name:"affected", value:"'cacti' package(s) on Debian 3.0, Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"0.6.7-2.5", rls:"DEB3.0"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cacti", ver:"0.8.6c-7sarge2", rls:"DEB3.1"))) {
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
