# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703551");
  script_cve_id("CVE-2015-8836", "CVE-2015-8837");
  script_tag(name:"creation_date", value:"2016-04-15 22:00:00 +0000 (Fri, 15 Apr 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-03-30 15:01:41 +0000 (Wed, 30 Mar 2016)");

  script_name("Debian: Security Advisory (DSA-3551-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DSA-3551-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3551-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3551");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'fuseiso' package(s) announced via the DSA-3551-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that fuseiso, a user-space implementation of the ISO 9660 file system based on FUSE, contains several vulnerabilities.

CVE-2015-8836

A stack-based buffer overflow may allow attackers who can trick a user into mounting a crafted ISO 9660 file system to cause a denial of service (crash), or, potentially, execute arbitrary code.

CVE-2015-8837

An integer overflow leads to a heap-based buffer overflow, which allows an attacker (who can trick a user into mounting a crafted ISO 9660 file system) to cause a denial of service (crash), or, potentially, execute arbitrary code.

For the oldstable distribution (wheezy), these problems have been fixed in version 20070708-3+deb7u1.

The stable distribution (jessie) does not contain fuseiso packages.

For the unstable distribution (sid), these problems have been fixed in version 20070708-3.2.

We recommend that you upgrade your fuseiso packages.");

  script_tag(name:"affected", value:"'fuseiso' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"fuseiso", ver:"20070708-3+deb7u1", rls:"DEB7"))) {
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
