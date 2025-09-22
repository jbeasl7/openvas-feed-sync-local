# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703823");
  script_cve_id("CVE-2017-6964");
  script_tag(name:"creation_date", value:"2017-03-27 22:00:00 +0000 (Mon, 27 Mar 2017)");
  script_version("2024-02-02T05:06:06+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:06 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-21 01:37:24 +0000 (Sun, 21 Jan 2024)");

  script_name("Debian: Security Advisory (DSA-3823-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3823-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/DSA-3823-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3823");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'eject' package(s) announced via the DSA-3823-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ilja Van Sprundel discovered that the dmcrypt-get-device helper used to check if a given device is an encrypted device handled by devmapper, and used in eject, does not check return values from setuid() and setgid() when dropping privileges.

For the stable distribution (jessie), this problem has been fixed in version 2.1.5+deb1+cvs20081104-13.1+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 2.1.5+deb1+cvs20081104-13.2.

We recommend that you upgrade your eject packages.");

  script_tag(name:"affected", value:"'eject' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"eject", ver:"2.1.5+deb1+cvs20081104-13.1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"eject-udeb", ver:"2.1.5+deb1+cvs20081104-13.1+deb8u1", rls:"DEB8"))) {
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
