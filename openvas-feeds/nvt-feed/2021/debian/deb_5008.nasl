# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.705008");
  script_cve_id("CVE-2021-37701", "CVE-2021-37712");
  script_tag(name:"creation_date", value:"2021-11-14 02:00:08 +0000 (Sun, 14 Nov 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-09 18:02:56 +0000 (Thu, 09 Sep 2021)");

  script_name("Debian: Security Advisory (DSA-5008-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5008-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2021/DSA-5008-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5008");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/node-tar");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'node-tar' package(s) announced via the DSA-5008-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the symlink extraction protections in node-tar, a Tar archives module for Node.js could by bypassed, allowing a malicious Tar archive to symlink into an arbitrary location.

For the stable distribution (bullseye), these problems have been fixed in version 6.0.5+ds1+~cs11.3.9-1+deb11u2.

We recommend that you upgrade your node-tar packages.

For the detailed security status of node-tar please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'node-tar' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"node-tar", ver:"6.0.5+ds1+~cs11.3.9-1+deb11u2", rls:"DEB11"))) {
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
