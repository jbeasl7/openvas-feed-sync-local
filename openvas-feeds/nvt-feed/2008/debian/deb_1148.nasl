# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.57264");
  script_cve_id("CVE-2005-2734", "CVE-2006-0330", "CVE-2006-4030");
  script_tag(name:"creation_date", value:"2008-01-17 22:13:11 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-1148-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.1");

  script_xref(name:"Advisory-ID", value:"DSA-1148-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2006/DSA-1148-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-1148");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gallery' package(s) announced via the DSA-1148-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in gallery, a web-based photo album. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2005-2734

A cross-site scripting vulnerability allows injection of web script code through HTML or EXIF information.

CVE-2006-0330

A cross-site scripting vulnerability in the user registration allows injection of web script code.

CVE-2006-4030

Missing input sanitising in the stats modules allows information disclosure.

For the stable distribution (sarge) these problems have been fixed in version 1.5-1sarge2.

For the unstable distribution (sid) these problems have been fixed in version 1.5-2.

We recommend that you upgrade your gallery package.");

  script_tag(name:"affected", value:"'gallery' package(s) on Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gallery", ver:"1.5-1sarge2", rls:"DEB3.1"))) {
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
