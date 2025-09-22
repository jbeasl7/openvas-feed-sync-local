# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53352");
  script_cve_id("CVE-2003-0173");
  script_tag(name:"creation_date", value:"2008-01-17 21:28:10 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-283)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-283");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-283");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-283");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xfsdump' package(s) announced via the DSA-283 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ethan Benson discovered a problem in xfsdump, that contains administrative utilities for the XFS filesystem. When filesystem quotas are enabled xfsdump runs xfsdq to save the quota information into a file at the root of the filesystem being dumped. The manner in which this file is created is unsafe.

While fixing this, a new option '-f path' has been added to xfsdq(8) to specify an output file instead of using the standard output stream. This file is created by xfsdq and xfsdq will fail to run if it exists already. The file is also created with a more appropriate mode than whatever the umask happened to be when xfsdump(8) was run.

For the stable distribution (woody) this problem has been fixed in version 2.0.1-2.

The old stable distribution (potato) is not affected since it doesn't contain xfsdump packages.

For the unstable distribution (sid) this problem has been fixed in version 2.2.8-1.

We recommend that you upgrade your xfsdump package immediately.");

  script_tag(name:"affected", value:"'xfsdump' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"xfsdump", ver:"2.0.1-2", rls:"DEB3.0"))) {
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
