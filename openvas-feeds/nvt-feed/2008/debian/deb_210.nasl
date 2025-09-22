# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53858");
  script_cve_id("CVE-2002-1405");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-210)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-210");
  script_xref(name:"URL", value:"https://www.debian.org/security/2002/DSA-210");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-210");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'lynx, lynx-ssl' package(s) announced via the DSA-210 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"lynx (a text-only web browser) did not properly check for illegal characters in all places, including processing of command line options, which could be used to insert extra HTTP headers in a request.

For Debian GNU/Linux 2.2/potato this has been fixed in version 2.8.3-1.1 of the lynx package and version 2.8.3.1-1.1 of the lynx-ssl package.

For Debian GNU/Linux 3.0/woody this has been fixed in version 2.8.4.1b-3.2 of the lynx package and version 1:2.8.4.1b-3.1 of the lynx-ssl package.");

  script_tag(name:"affected", value:"'lynx, lynx-ssl' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"lynx", ver:"2.8.3-1.1", rls:"DEB3.0"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lynx-ssl", ver:"2.8.3.1-1.1", rls:"DEB3.0"))) {
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
