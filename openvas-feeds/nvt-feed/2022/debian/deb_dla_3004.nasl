# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.893004");
  script_cve_id("CVE-2022-27114");
  script_tag(name:"creation_date", value:"2022-05-14 01:00:11 +0000 (Sat, 14 May 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-17 16:33:00 +0000 (Tue, 17 May 2022)");

  script_name("Debian: Security Advisory (DLA-3004-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-3004-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2022/DLA-3004-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'htmldoc' package(s) announced via the DLA-3004-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was an integer overflow vulnerabiliity in htmldoc, a HTML processor that generates indexed HTML, PS and PDF files. This was caused by a programming error in image_load_jpeg function due to a conflation or confusion of declared/expected/observed image dimensions.

CVE-2022-27114

CVE-2022-27114: There is a vulnerability in htmldoc 1.9.16. In image_load_jpeg function image.cxx when it calls malloc,'img->width' and 'img->height' they are large enough to cause an integer overflow. So, the malloc function may return a heap block smaller than the expected size, and it will cause a buffer overflow/Address boundary error in the jpeg_read_scanlines function.

For Debian 9 Stretch, these problems have been fixed in version 1.8.27-8+deb9u3.

We recommend that you upgrade your htmldoc packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'htmldoc' package(s) on Debian 9.");

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

if(release == "DEB9") {

  if(!isnull(res = isdpkgvuln(pkg:"htmldoc", ver:"1.8.27-8+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"htmldoc-common", ver:"1.8.27-8+deb9u3", rls:"DEB9"))) {
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
