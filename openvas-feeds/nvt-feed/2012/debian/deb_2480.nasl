# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.72206");
  script_cve_id("CVE-2011-2082", "CVE-2011-2083", "CVE-2011-2084", "CVE-2011-2085", "CVE-2011-4458", "CVE-2011-4459", "CVE-2011-4460");
  script_tag(name:"creation_date", value:"2012-09-19 07:27:39 +0000 (Wed, 19 Sep 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2480-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DSA-2480-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2012/DSA-2480-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2480");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'request-tracker3.8' package(s) announced via the DSA-2480-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in Request Tracker, an issue tracking system:

CVE-2011-2082

The vulnerable-passwords scripts introduced for CVE-2011-0009 failed to correct the password hashes of disabled users.

CVE-2011-2083

Several cross-site scripting issues have been discovered.

CVE-2011-2084

Password hashes could be disclosed by privileged users.

CVE-2011-2085

Several cross-site request forgery vulnerabilities have been found. If this update breaks your setup, you can restore the old behaviour by setting $RestrictReferrer to 0.

CVE-2011-4458

The code to support variable envelope return paths allowed the execution of arbitrary code.

CVE-2011-4459

Disabled groups were not fully accounted as disabled.

CVE-2011-4460

SQL injection vulnerability, only exploitable by privileged users.

Please note that if you run request-tracker3.8 under the Apache web server, you must stop and start Apache manually. The restart mechanism is not recommended, especially when using mod_perl.

For the stable distribution (squeeze), these problems have been fixed in version 3.8.8-7+squeeze5.

For the unstable distribution (sid), these problems have been fixed in version 4.0.5-3.

We recommend that you upgrade your request-tracker3.8 packages.");

  script_tag(name:"affected", value:"'request-tracker3.8' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"request-tracker3.8", ver:"3.8.8-7+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.8-apache2", ver:"3.8.8-7+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.8-clients", ver:"3.8.8-7+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.8-db-mysql", ver:"3.8.8-7+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.8-db-postgresql", ver:"3.8.8-7+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"rt3.8-db-sqlite", ver:"3.8.8-7+squeeze2", rls:"DEB6"))) {
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
