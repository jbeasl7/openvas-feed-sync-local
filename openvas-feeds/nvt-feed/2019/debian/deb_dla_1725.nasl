# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891725");
  script_cve_id("CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843", "CVE-2018-5764");
  script_tag(name:"creation_date", value:"2019-03-24 22:00:00 +0000 (Sun, 24 Mar 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-06-01 16:47:18 +0000 (Thu, 01 Jun 2017)");

  script_name("Debian: Security Advisory (DLA-1725-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1725-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1725-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'rsync' package(s) announced via the DLA-1725-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Trail of Bits used the automated vulnerability discovery tools developed for the DARPA Cyber Grand Challenge to audit zlib. As rsync, a fast, versatile, remote (and local) file-copying tool, uses an embedded copy of zlib, those issues are also present in rsync.

CVE-2016-9840

In order to avoid undefined behavior, remove offset pointer optimization, as this is not compliant with the C standard.

CVE-2016-9841

Only use post-increment to be compliant with the C standard.

CVE-2016-9842

In order to avoid undefined behavior, do not shift negative values, as this is not compliant with the C standard.

CVE-2016-9843

In order to avoid undefined behavior, do not pre-decrement a pointer in big-endian CRC calculation, as this is not compliant with the C standard.

CVE-2018-5764

Prevent remote attackers from being able to bypass the argument-sanitization protection mechanism by ignoring --protect-args when already sent by client.

For Debian 8 Jessie, these problems have been fixed in version 3.1.1-3+deb8u2.

We recommend that you upgrade your rsync packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'rsync' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"rsync", ver:"3.1.1-3+deb8u2", rls:"DEB8"))) {
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
