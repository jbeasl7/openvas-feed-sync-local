# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892742");
  script_cve_id("CVE-2020-21041", "CVE-2020-22015", "CVE-2020-22016", "CVE-2020-22020", "CVE-2020-22021", "CVE-2020-22022", "CVE-2020-22023", "CVE-2020-22025", "CVE-2020-22026", "CVE-2020-22028", "CVE-2020-22031", "CVE-2020-22032", "CVE-2020-22036", "CVE-2021-3566", "CVE-2021-38114");
  script_tag(name:"creation_date", value:"2021-08-16 03:00:18 +0000 (Mon, 16 Aug 2021)");
  script_version("2024-02-02T05:06:07+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:07 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-09 00:53:46 +0000 (Wed, 09 Jun 2021)");

  script_name("Debian: Security Advisory (DLA-2742-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"Advisory-ID", value:"DLA-2742-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2021/DLA-2742-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ffmpeg");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ffmpeg' package(s) announced via the DLA-2742-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple issues have been discovered in ffmpeg.

CVE-2020-21041

Buffer Overflow vulnerability exists via apng_do_inverse_blend in libavcodec/pngenc.c, which could let a remote malicious user cause a Denial of Service.

CVE-2020-22015

Buffer Overflow vulnerability in mov_write_video_tag due to the out of bounds in libavformat/movenc.c, which could let a remote malicious user obtain sensitive information, cause a Denial of Service, or execute arbitrary code.

CVE-2020-22016

A heap-based Buffer Overflow vulnerability at libavcodec/get_bits.h when writing .mov files, which might lead to memory corruption and other potential consequences.

CVE-2020-22020

Buffer Overflow vulnerability in the build_diff_map function in libavfilter/vf_fieldmatch.c, which could let a remote malicious user cause a Denial of Service.

CVE-2020-22021

Buffer Overflow vulnerability at filter_edges function in libavfilter/vf_yadif.c, which could let a remote malicious user cause a Denial of Service.

CVE-2020-22022

A heap-based Buffer Overflow vulnerability exists in filter_frame at libavfilter/vf_fieldorder.c, which might lead to memory corruption and other potential consequences.

CVE-2020-22023

A heap-based Buffer Overflow vulnerabililty exists in filter_frame at libavfilter/vf_bitplanenoise.c, which might lead to memory corruption and other potential consequences.

CVE-2020-22025

A heap-based Buffer Overflow vulnerability exists in gaussian_blur at libavfilter/vf_edgedetect.c, which might lead to memory corruption and other potential consequences.

CVE-2020-22026

Buffer Overflow vulnerability exists in the config_input function at libavfilter/af_tremolo.c, which could let a remote malicious user cause a Denial of Service.

CVE-2020-22028

Buffer Overflow vulnerability in filter_vertically_8 at libavfilter/vf_avgblur.c, which could cause a remote Denial of Service.

CVE-2020-22031

A Heap-based Buffer Overflow vulnerability in filter16_complex_low, which might lead to memory corruption and other potential consequences.

CVE-2020-22032

A heap-based Buffer Overflow vulnerability in gaussian_blur, which might lead to memory corruption and other potential consequences.

CVE-2020-22036

A heap-based Buffer Overflow vulnerability in filter_intra at libavfilter/vf_bwdif.c, which might lead to memory corruption and other potential consequences.

CVE-2021-3566

The tty demuxer did not have a read_probe function assigned to it. By crafting a legitimate ffconcat file that references an image, followed by a file the triggers the tty demuxer, the contents of the second file will be copied into the output file verbatim (as long as the `-vcodec copy` option is passed to ffmpeg).

CVE-2021-38114

libavcodec/dnxhddec.c does not check the return value of the init_vlc function. Crafted DNxHD data can cause unspecified impact.

For Debian 9 stretch, these problems have been fixed in version ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ffmpeg' package(s) on Debian 9.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ffmpeg-doc", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libav-tools", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-dev", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec-extra57", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavcodec57", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice-dev", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavdevice57", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-dev", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter-extra6", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavfilter6", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat-dev", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavformat57", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavresample-dev", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavresample3", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil-dev", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libavutil55", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc-dev", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpostproc54", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswresample-dev", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswresample2", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale-dev", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libswscale4", ver:"7:3.2.15-0+deb9u3", rls:"DEB9"))) {
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
