# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.60618");
  script_cve_id("CVE-2007-6205", "CVE-2008-0124", "CVE-2008-1476");
  script_tag(name:"creation_date", value:"2008-03-27 17:25:13 +0000 (Thu, 27 Mar 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_name("Debian: Security Advisory (DSA-1528-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB4");

  script_xref(name:"Advisory-ID", value:"DSA-1528-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2008/DSA-1528-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1528");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'serendipity' package(s) announced via the DSA-1528-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Peter Huwe and Hanno Bock discovered that Serendipity, a weblog manager, did not properly sanitise input to several scripts which allowed cross site scripting.

The old stable distribution (sarge) does not contain a serendipity package.

For the stable distribution (etch), this problem has been fixed in version 1.0.4-1+etch1.

For the unstable distribution (sid), this problem has been fixed in version 1.3-1.

We recommend that you upgrade your serendipity package.");

  script_tag(name:"affected", value:"'serendipity' package(s) on Debian 4.");

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

  if(!isnull(res = isdpkgvuln(pkg:"serendipity", ver:"1.0.4-1+etch1", rls:"DEB4"))) {
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
