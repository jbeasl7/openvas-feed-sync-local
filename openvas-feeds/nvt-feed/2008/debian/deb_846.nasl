# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.55541");
  script_cve_id("CVE-2005-1111", "CVE-2005-1229");
  script_tag(name:"creation_date", value:"2008-01-17 22:03:37 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-02T05:06:04+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:04 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 17:07:14 +0000 (Fri, 26 Jan 2024)");

  script_name("Debian: Security Advisory (DSA-846-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(3\.0|3\.1)");

  script_xref(name:"Advisory-ID", value:"DSA-846-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2005/DSA-846-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-846");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'cpio' package(s) announced via the DSA-846-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two vulnerabilities have been discovered in cpio, a program to manage archives of files. The Common Vulnerabilities and Exposures project identifies the following problems:

CAN-2005-1111

Imran Ghory discovered a race condition in setting the file permissions of files extracted from cpio archives. A local attacker with write access to the target directory could exploit this to alter the permissions of arbitrary files the extracting user has write permissions for.

CAN-2005-1229

Imran Ghory discovered that cpio does not sanitise the path of extracted files even if the --no-absolute-filenames option was specified. This can be exploited to install files in arbitrary locations where the extracting user has write permissions to.

For the old stable distribution (woody) these problems have been fixed in version 2.4.2-39woody2.

For the stable distribution (sarge) these problems have been fixed in version 2.5-1.3.

For the unstable distribution (sid) these problems have been fixed in version 2.6-6.

We recommend that you upgrade your cpio package.");

  script_tag(name:"affected", value:"'cpio' package(s) on Debian 3.0, Debian 3.1.");

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

  if(!isnull(res = isdpkgvuln(pkg:"cpio", ver:"2.4.2-39woody2", rls:"DEB3.0"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"cpio", ver:"2.5-1.3", rls:"DEB3.1"))) {
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
