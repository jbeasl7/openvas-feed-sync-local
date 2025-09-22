# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.58593");
  script_cve_id("CVE-2006-6942", "CVE-2006-6944", "CVE-2007-1325", "CVE-2007-1395", "CVE-2007-2245");
  script_tag(name:"creation_date", value:"2008-01-17 22:19:52 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-1370-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.1|4)");

  script_xref(name:"Advisory-ID", value:"DSA-1370-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2007/DSA-1370-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1370");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'phpmyadmin' package(s) announced via the DSA-1370-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in phpMyAdmin, a program to administrate MySQL over the web. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2007-1325

The PMA_ArrayWalkRecursive function in libraries/common.lib.php does not limit recursion on arrays provided by users, which allows context-dependent attackers to cause a denial of service (web server crash) via an array with many dimensions.

This issue affects only the stable distribution (Etch).

CVE-2007-1395

Incomplete blacklist vulnerability in index.php allows remote attackers to conduct cross-site scripting (XSS) attacks by injecting arbitrary JavaScript or HTML in a (1) db or (2) table parameter value followed by an uppercase </SCRIPT> end tag, which bypasses the protection against lowercase </script>.

This issue affects only the stable distribution (Etch).

CVE-2007-2245

Multiple cross-site scripting (XSS) vulnerabilities allow remote attackers to inject arbitrary web script or HTML via (1) the fieldkey parameter to browse_foreigners.php or (2) certain input to the PMA_sanitize function.

CVE-2006-6942

Multiple cross-site scripting (XSS) vulnerabilities allow remote attackers to inject arbitrary HTML or web script via (1) a comment for a table name, as exploited through (a) db_operations.php, (2) the db parameter to (b) db_create.php, (3) the newname parameter to db_operations.php, the (4) query_history_latest, (5) query_history_latest_db, and (6) querydisplay_tab parameters to (c) querywindow.php, and (7) the pos parameter to (d) sql.php.

This issue affects only the oldstable distribution (Sarge).

CVE-2006-6944

phpMyAdmin allows remote attackers to bypass Allow/Deny access rules that use IP addresses via false headers.

This issue affects only the oldstable distribution (Sarge).

For the old stable distribution (sarge) these problems have been fixed in version 2.6.2-3sarge5.

For the stable distribution (etch) these problems have been fixed in version 2.9.1.1-4.

For the unstable distribution (sid) these problems have been fixed in version 2.10.1-1.

We recommend that you upgrade your phpmyadmin packages.");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Debian 3.1, Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:2.6.2-3sarge5", rls:"DEB3.1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB4") {

  if(!isnull(res = isdpkgvuln(pkg:"phpmyadmin", ver:"4:2.9.1.1-4", rls:"DEB4"))) {
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
