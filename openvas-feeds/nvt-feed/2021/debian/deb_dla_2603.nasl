# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892603");
  script_cve_id("CVE-2019-11372", "CVE-2019-11373", "CVE-2020-15395", "CVE-2020-26797");
  script_tag(name:"creation_date", value:"2021-03-24 04:00:14 +0000 (Wed, 24 Mar 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-02 19:38:33 +0000 (Thu, 02 Jul 2020)");

  script_name("Debian: Security Advisory (DLA-2603-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2603-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2603-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libmediainfo' package(s) announced via the DLA-2603-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there were a number of vulnerabilities in libmediainfo, a library reading metadata such as track names, lengths, etc. from media files.

CVE-2019-11372

An out-of-bounds read in MediaInfoLib::File__Tags_Helper::Synched_Test in Tag/File__Tags.cpp in MediaInfoLib in MediaArea MediaInfo 18.12 leads to a crash.

CVE-2019-11373

An out-of-bounds read in File__Analyze::Get_L8 in File__Analyze_Buffer.cpp in MediaInfoLib in MediaArea MediaInfo 18.12 leads to a crash.

CVE-2020-15395

In MediaInfoLib in MediaArea MediaInfo 20.03, there is a stack-based buffer over-read in Streams_Fill_PerStream in Multiple/File_MpegPs.cpp (aka an off-by-one during MpegPs parsing).

CVE-2020-26797

Mediainfo before version 20.08 has a heap buffer overflow vulnerability via MediaInfoLib::File_Gxf::ChooseParser_ChannelGrouping.

For Debian 9 Stretch, these problems have been fixed in version 0.7.91-1+deb9u1.

We recommend that you upgrade your libmediainfo packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libmediainfo' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libmediainfo-dev", ver:"0.7.91-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmediainfo-doc", ver:"0.7.91-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libmediainfo0v5", ver:"0.7.91-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-mediainfodll", ver:"0.7.91-1+deb9u1", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-mediainfodll", ver:"0.7.91-1+deb9u1", rls:"DEB9"))) {
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
