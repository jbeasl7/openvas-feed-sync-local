# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892765");
  script_cve_id("CVE-2016-10246", "CVE-2016-10247", "CVE-2017-6060", "CVE-2018-1000036", "CVE-2018-10289", "CVE-2020-19609");
  script_tag(name:"creation_date", value:"2021-09-24 01:03:00 +0000 (Fri, 24 Sep 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-16 19:10:32 +0000 (Thu, 16 Mar 2017)");

  script_name("Debian: Security Advisory (DLA-2765-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2765-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2765-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mupdf");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mupdf' package(s) announced via the DLA-2765-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues have been discovered in mupdf.

CVE-2016-10246

Buffer overflow in the main function in jstest_main.c allows remote attackers to cause a denial of service (out-of-bounds write) via a crafted file.

CVE-2016-10247

Buffer overflow in the my_getline function in jstest_main.c allows remote attackers to cause a denial of service (out-of-bounds write) via a crafted file.

CVE-2017-6060

Stack-based buffer overflow in jstest_main.c allows remote attackers to have unspecified impact via a crafted image.


CVE-2018-10289

An infinite loop in the fz_skip_space function of the pdf/pdf-xref.c file. A remote adversary could leverage this vulnerability to cause a denial of service via a crafted pdf file.

CVE-2018-1000036

Multiple memory leaks in the PDF parser allow an attacker to cause a denial of service (memory leak) via a crafted file.


CVE-2020-19609

A heap based buffer over-write in tiff_expand_colormap() function when parsing TIFF files allowing attackers to cause a denial of service.

For Debian 9 stretch, these problems have been fixed in version 1.14.0+ds1-4+deb9u1.

We recommend that you upgrade your mupdf packages.

For the detailed security status of mupdf please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'mupdf' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmupdf-dev", ver:"1.14.0+ds1-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mupdf", ver:"1.14.0+ds1-4+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mupdf-tools", ver:"1.14.0+ds1-4+deb9u1", rls:"DEB9"))) {
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
