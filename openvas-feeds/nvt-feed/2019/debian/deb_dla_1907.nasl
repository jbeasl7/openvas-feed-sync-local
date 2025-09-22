# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891907");
  script_cve_id("CVE-2017-9987", "CVE-2018-11102", "CVE-2018-5766", "CVE-2019-14371", "CVE-2019-14372", "CVE-2019-14442");
  script_tag(name:"creation_date", value:"2019-09-03 02:00:17 +0000 (Tue, 03 Sep 2019)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-05 13:26:27 +0000 (Mon, 05 Aug 2019)");

  script_name("Debian: Security Advisory (DLA-1907-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1907-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2019/DLA-1907-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libav' package(s) announced via the DLA-1907-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security issues have been corrected in multiple demuxers and decoders of the libav multimedia library.

CVE-2017-9987

In Libav, there was a heap-based buffer overflow in the function hpel_motion in mpegvideo_motion.c. A crafted input could have lead to a remote denial of service attack.

CVE-2018-5766

In Libav there was an invalid memcpy in the av_packet_ref function of libavcodec/avpacket.c. Remote attackers could have leveraged this vulnerability to cause a denial of service (segmentation fault) via a crafted avi file.

CVE-2018-11102

A read access violation in the mov_probe function in libavformat/mov.c allowed remote attackers to cause a denial of service (application crash), as demonstrated by avconv.

CVE-2019-14372

In Libav, there was an infinite loop in the function wv_read_block_header() in the file wvdec.c.

CVE-2019-14442

In mpc8_read_header in libavformat/mpc8.c, an input file could have resulted in an avio_seek infinite loop and hang, with 100% CPU consumption. Attackers could have leveraged this vulnerability to cause a denial of service via a crafted file.

For Debian 8 Jessie, these problems have been fixed in version 6:11.12-1~deb8u8.

We recommend that you upgrade your libav packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libav' package(s) on Debian 8.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libav-dbg", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libav-doc", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libav-tools", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-dev", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra-56", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec56", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice-dev", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice55", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-dev", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter5", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat-dev", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat56", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavresample-dev", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavresample2", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil-dev", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil54", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale-dev", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale3", ver:"6:11.12-1~deb8u8", rls:"DEB8"))) {
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
