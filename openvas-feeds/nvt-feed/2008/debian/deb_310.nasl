# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.53600");
  script_cve_id("CVE-2003-0385");
  script_tag(name:"creation_date", value:"2008-01-17 21:36:24 +0000 (Thu, 17 Jan 2008)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Debian: Security Advisory (DSA-310)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB3\.0");

  script_xref(name:"Advisory-ID", value:"DSA-310");
  script_xref(name:"URL", value:"https://www.debian.org/security/2003/DSA-310");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-310");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xaos' package(s) announced via the DSA-310 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"XaoS, a program for displaying fractal images, is installed setuid root on certain architectures in order to use svgalib, which requires access to the video hardware. However, it is not designed for secure setuid execution, and can be exploited to gain root privileges.

In these updated packages, the setuid bit has been removed from the xaos binary. Users who require the svgalib functionality should grant these privileges only to a trusted group.

This vulnerability is exploitable in version 3.0-18 (potato) on i386 and alpha architectures, and in version 3.0-23 (woody) on the i386 architecture only.

For the stable distribution (woody) this problem has been fixed in version 3.0-23woody1.

For the old stable distribution (potato) this problem has been fixed in version 3.0-18potato1.

For the unstable distribution (sid) this problem has been fixed in version 3.1r-4.

We recommend that you update your xaos package.");

  script_tag(name:"affected", value:"'xaos' package(s) on Debian 3.0.");

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

  if(!isnull(res = isdpkgvuln(pkg:"xaos", ver:"3.0-23woody1", rls:"DEB3.0"))) {
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
