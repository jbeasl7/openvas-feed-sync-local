# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.70695");
  script_cve_id("CVE-2011-4339");
  script_tag(name:"creation_date", value:"2012-02-11 08:22:50 +0000 (Sat, 11 Feb 2012)");
  script_version("2024-02-01T14:37:10+0000");
  script_tag(name:"last_modification", value:"2024-02-01 14:37:10 +0000 (Thu, 01 Feb 2024)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2376-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2376-2");
  script_xref(name:"URL", value:"https://www.debian.org/security/2011/DSA-2376-2");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-2376");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ipmitool' package(s) announced via the DSA-2376-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that OpenIPMI, the Intelligent Platform Management Interface library and tools, used too wide permissions PID file, which allows local users to kill arbitrary processes by writing to this file.

For the oldstable distribution (lenny), this problem has been fixed in version 1.8.9-2+squeeze1. (Although the version number contains the string squeeze, this is in fact an update for lenny.)

For the stable distribution (squeeze), this problem has been fixed in version 1.8.11-2+squeeze2.

For the unstable distribution (sid), this problem has been fixed in version 1.8.11-5.

We recommend that you upgrade your ipmitool packages.");

  script_tag(name:"affected", value:"'ipmitool' package(s) on Debian 5.");

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

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"ipmitool", ver:"1.8.9-2+squeeze1", rls:"DEB5"))) {
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
