# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703577");
  script_cve_id("CVE-2016-4425");
  script_tag(name:"creation_date", value:"2016-05-13 22:00:00 +0000 (Fri, 13 May 2016)");
  script_version("2024-02-02T05:06:05+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:05 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-05-18 00:24:39 +0000 (Wed, 18 May 2016)");

  script_name("Debian: Security Advisory (DSA-3577-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DSA-3577-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/DSA-3577-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-3577");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'jansson' package(s) announced via the DSA-3577-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gustavo Grieco discovered that jansson, a C library for encoding, decoding and manipulating JSON data, did not limit the recursion depth when parsing JSON arrays and objects. This could allow remote attackers to cause a denial of service (crash) via stack exhaustion, using crafted JSON data.

For the stable distribution (jessie), this problem has been fixed in version 2.7-1+deb8u1.

For the unstable distribution (sid), this problem has been fixed in version 2.7-5.

We recommend that you upgrade your jansson packages.");

  script_tag(name:"affected", value:"'jansson' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libjansson-dbg", ver:"2.7-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjansson-dev", ver:"2.7-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjansson-doc", ver:"2.7-1+deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libjansson4", ver:"2.7-1+deb8u1", rls:"DEB8"))) {
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
