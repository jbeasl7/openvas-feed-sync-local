# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.702882");
  script_cve_id("CVE-2013-5951");
  script_tag(name:"creation_date", value:"2014-03-19 23:00:00 +0000 (Wed, 19 Mar 2014)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-2882-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(6|7)");

  script_xref(name:"Advisory-ID", value:"DSA-2882-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2014/DSA-2882-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2882");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'extplorer' package(s) announced via the DSA-2882-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple cross-site scripting (XSS) vulnerabilities have been discovered in extplorer, a web file explorer and manager using Ext JS. A remote attacker can inject arbitrary web script or HTML code via a crafted string in the URL to application.js.php, admin.php, copy_move.php, functions.php, header.php and upload.php.

For the oldstable distribution (squeeze), this problem has been fixed in version 2.1.0b6+dfsg.2-1+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in version 2.1.0b6+dfsg.3-4+deb7u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your extplorer packages.");

  script_tag(name:"affected", value:"'extplorer' package(s) on Debian 6, Debian 7.");

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

  if(!isnull(res = isdpkgvuln(pkg:"extplorer", ver:"2.1.0b6+dfsg.2-1+squeeze2", rls:"DEB6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"extplorer", ver:"2.1.0b6+dfsg.3-4+deb7u1", rls:"DEB7"))) {
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
