# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58338");
  script_cve_id("CVE-2006-7191", "CVE-2007-1840");
  script_tag(name:"creation_date", value:"2008-01-17 22:17:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1287-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1287-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1287-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1287");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ldap-account-manager' package(s) announced via the DSA-1287-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been identified in the version of ldap-account-manager shipped with Debian 3.1 (sarge).

CVE-2006-7191

An untrusted PATH vulnerability could allow a local attacker to execute arbitrary code with elevated privileges by providing a malicious rm executable and specifying a PATH environment variable referencing this executable.

CVE-2007-1840

Improper escaping of HTML content could allow an attacker to execute a cross-site scripting attack (XSS) and execute arbitrary code in the victim's browser in the security context of the affected web site.

For the old stable distribution (sarge), this problem has been fixed in version 0.4.9-2sarge1. Newer versions of Debian (etch, lenny, and sid), are not affected.

We recommend that you upgrade your ldap-account-manager package.");

  script_tag(name:"affected", value:"'ldap-account-manager' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ldap-account-manager", ver:"0.4.9-2sarge1", rls:"DEB3.1"))) {
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
