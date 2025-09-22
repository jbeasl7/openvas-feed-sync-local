# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3603");
  script_cve_id("CVE-2023-43788", "CVE-2023-43789");
  script_tag(name:"creation_date", value:"2023-10-06 04:21:16 +0000 (Fri, 06 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-17 18:05:37 +0000 (Tue, 17 Oct 2023)");

  script_name("Debian: Security Advisory (DLA-3603-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3603-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3603-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libxpm");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libxpm' package(s) announced via the DLA-3603-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in libXpm, the X Pixmap (XPM) image library.

CVE-2023-43786

Yair Mizrahi discovered an infinite recursion issue when parsing crafted XPM files, which would result in denial of service.

CVE-2023-43787

Yair Mizrahi discovered a buffer overflow vulnerability in libX11 when parsing crafted XPM files, which could result in denial of service or potentially the execution of arbitrary code.

CVE-2023-43788

Alan Coopersmith found an out of bounds read in XpmCreateXpmImageFromBuffer, which could result in denial of service when parsing crafted XPM files.

CVE-2023-43789

Alan Coopersmith discovered an out of bounds read issue when parsing corrupted colormaps, which could lead to denial of service when parsing crafted XPM files.

For Debian 10 buster, these problems have been fixed in version 1:3.5.12-1+deb10u2.

We recommend that you upgrade your libxpm packages.

For the detailed security status of libxpm please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libxpm' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"libxpm-dev", ver:"1:3.5.12-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxpm4", ver:"1:3.5.12-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xpmutils", ver:"1:3.5.12-1+deb10u2", rls:"DEB10"))) {
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
