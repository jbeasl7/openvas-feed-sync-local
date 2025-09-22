# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893223");
  script_cve_id("CVE-2018-11490", "CVE-2019-15133");
  script_tag(name:"creation_date", value:"2022-12-06 02:00:30 +0000 (Tue, 06 Dec 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-02 15:41:33 +0000 (Mon, 02 Jul 2018)");

  script_name("Debian: Security Advisory (DLA-3223-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3223-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3223-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/giflib");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'giflib' package(s) announced via the DLA-3223-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes two file format vulnerabilities in giflib.

CVE-2018-11490

The DGifDecompressLine function in dgif_lib.c, as later shipped in cgif.c in sam2p 0.49.4, has a heap-based buffer overflow because a certain 'Private->RunningCode - 2' array index is not checked. This will lead to a denial of service or possibly unspecified other impact.

CVE-2019-15133

A malformed GIF file triggers a divide-by-zero exception in the decoder function DGifSlurp in dgif_lib.c if the height field of the ImageSize data structure is equal to zero.

For Debian 10 buster, these problems have been fixed in version 5.1.4-3+deb10u1.

We recommend that you upgrade your giflib packages.

For the detailed security status of giflib please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'giflib' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"giflib-tools", ver:"5.1.4-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgif-dev", ver:"5.1.4-3+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgif7", ver:"5.1.4-3+deb10u1", rls:"DEB10"))) {
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
