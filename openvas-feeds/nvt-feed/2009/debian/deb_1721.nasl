# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.63395");
  script_cve_id("CVE-2009-0360", "CVE-2009-0361");
  script_tag(name:"creation_date", value:"2009-02-13 19:43:17 +0000 (Fri, 13 Feb 2009)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-1721-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1721-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2009/DSA-1721-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1721");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libpam-krb5' package(s) announced via the DSA-1721-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several local vulnerabilities have been discovered in the PAM module for MIT Kerberos. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2009-0360

Russ Allbery discovered that the Kerberos PAM module parsed configuration settings from environment variables when run from a setuid context. This could lead to local privilege escalation if an attacker points a setuid program using PAM authentication to a Kerberos setup under her control.

CVE-2009-0361

Derek Chan discovered that the Kerberos PAM module allows reinitialisation of user credentials when run from a setuid context, resulting in potential local denial of service by overwriting the credential cache file or to privilege escalation.

For the stable distribution (etch), these problems have been fixed in version 2.6-1etch1.

For the upcoming stable distribution (lenny), these problems have been fixed in version 3.11-4.

For the unstable distribution (sid), these problems will be fixed soon.

We recommend that you upgrade your libpam-krb5 package.");

  script_tag(name:"affected", value:"'libpam-krb5' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpam-krb5", ver:"2.6-1etch1", rls:"DEB4"))) {
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
