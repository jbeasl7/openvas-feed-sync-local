# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0040");
  script_cve_id("CVE-2024-47537", "CVE-2024-47538", "CVE-2024-47539", "CVE-2024-47540", "CVE-2024-47541", "CVE-2024-47542", "CVE-2024-47543", "CVE-2024-47544", "CVE-2024-47545", "CVE-2024-47546", "CVE-2024-47596", "CVE-2024-47597", "CVE-2024-47598", "CVE-2024-47599", "CVE-2024-47600", "CVE-2024-47601", "CVE-2024-47602");
  script_tag(name:"creation_date", value:"2025-02-07 04:11:11 +0000 (Fri, 07 Feb 2025)");
  script_version("2025-02-07T05:37:57+0000");
  script_tag(name:"last_modification", value:"2025-02-07 05:37:57 +0000 (Fri, 07 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-18 21:53:53 +0000 (Wed, 18 Dec 2024)");

  script_name("Mageia: Security Advisory (MGASA-2025-0040)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0040");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0040.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33856");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2024/msg00247.html");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2024/msg00248.html");
  script_xref(name:"URL", value:"https://lists.debian.org/debian-security-announce/2024/msg00254.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7174-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-7176-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2024/12/13/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer1.0, gstreamer1.0-plugins-base, gstreamer1.0-plugins-good' package(s) announced via the MGASA-2025-0040 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GStreamer has an OOB-write in isomp4/qtdemux.c. (CVE-2024-47537)
GStreamer has a stack-buffer overflow in
vorbis_handle_identification_packet. (CVE-2024-47538)
GStreamer has an OOB-write in convert_to_s334_1a. (CVE-2024-47539)
GStreamer uses uninitialized stack memory in Matroska/WebM demuxer.
(CVE-2024-47540)
GStreamer has an out-of-bounds write in SSA subtitle parser.
(CVE-2024-47541)
GStreamer ID3v2 parser out-of-bounds read and NULL-pointer dereference.
(CVE-2024-47542)
GStreamer has an OOB-read in qtdemux_parse_container. (CVE-2024-47543)
GStreamer has NULL-pointer dereferences in MP4/MOV demuxer CENC
handling. (CVE-2024-47544)
GStreamer has an integer underflow in FOURCC_strf parsing leading to
OOB-read. (CVE-2024-47545)
GStreamer has an integer underflow in extract_cc_from_data leading to
OOB-read. (CVE-2024-47546)
GStreamer has an OOB-read in FOURCC_SMI_ parsing. (CVE-2024-47596)
GStreamer has an OOB-read in qtdemux_parse_samples. (CVE-2024-47597)
GStreamer has an OOB-read in qtdemux_merge_sample_table.
(CVE-2024-47598)
GStreamer Insufficient error handling in JPEG decoder that can lead to
NULL-pointer dereferences. (CVE-2024-47599)
GStreamer has an OOB-read in format_channel_mask. (CVE-2024-47600)
GStreamer has a NULL-pointer dereference in Matroska/WebM demuxer.
(CVE-2024-47601)
GStreamer NULL-pointer dereferences and out-of-bounds reads in
Matroska/WebM demuxer. (CVE-2024-47602)
GStreamer NULL-pointer dereference in Matroska/WebM demuxer.
(CVE-2024-47603)
GStreamer Integer overflows in MP4/MOV demuxer and memory allocator that
can lead to out-of-bounds writes. (CVE-2024-47606)
Stack-buffer overflow in gst_opus_dec_parse_header. (CVE-2024-47607)
GStreamer has a null pointer dereference in gst_gdk_pixbuf_dec_flush.
(CVE-2024-47613)
GStreamer has an out-of-bounds write in Ogg demuxer. (CVE-2024-47615)
GStreamer has an OOB-read in gst_avi_subtitle_parse_gab2_chunk.
(CVE-2024-47774)
GStreamer has an OOB-read in parse_ds64. (CVE-2024-47775)
GStreamer has a OOB-read in gst_wavparse_cue_chunk. (CVE-2024-47776)
GStreamer has an OOB-read in gst_wavparse_smpl_chunk. (CVE-2024-47777)
GStreamer has an OOB-read in gst_wavparse_adtl_chunk. (CVE-2024-47778)
Gstreamer Use-After-Free read in Matroska CodecPrivate. (CVE-2024-47834)
Gstreamer NULL-pointer dereference in LRC subtitle parser.
(CVE-2024-47835)");

  script_tag(name:"affected", value:"'gstreamer1.0, gstreamer1.0-plugins-base, gstreamer1.0-plugins-good' package(s) on Mageia 9.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0", rpm:"gstreamer1.0~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-aalib", rpm:"gstreamer1.0-aalib~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-caca", rpm:"gstreamer1.0-caca~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-cdparanoia", rpm:"gstreamer1.0-cdparanoia~1.22.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-dv", rpm:"gstreamer1.0-dv~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-flac", rpm:"gstreamer1.0-flac~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-jack", rpm:"gstreamer1.0-jack~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-lame", rpm:"gstreamer1.0-lame~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-libvisual", rpm:"gstreamer1.0-libvisual~1.22.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-base", rpm:"gstreamer1.0-plugins-base~1.22.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-plugins-good", rpm:"gstreamer1.0-plugins-good~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-pulse", rpm:"gstreamer1.0-pulse~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-raw1394", rpm:"gstreamer1.0-raw1394~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-soup", rpm:"gstreamer1.0-soup~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-speex", rpm:"gstreamer1.0-speex~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-tools", rpm:"gstreamer1.0-tools~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-twolame", rpm:"gstreamer1.0-twolame~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-vp8", rpm:"gstreamer1.0-vp8~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer1.0-wavpack", rpm:"gstreamer1.0-wavpack~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gst-gir1.0", rpm:"lib64gst-gir1.0~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstgl-gir1.0", rpm:"lib64gstgl-gir1.0~1.22.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstgl1.0_0", rpm:"lib64gstgl1.0_0~1.22.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base-gir1.0", rpm:"lib64gstreamer-plugins-base-gir1.0~1.22.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base1.0-devel", rpm:"lib64gstreamer-plugins-base1.0-devel~1.22.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer-plugins-base1.0_0", rpm:"lib64gstreamer-plugins-base1.0_0~1.22.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer1.0-devel", rpm:"lib64gstreamer1.0-devel~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64gstreamer1.0_0", rpm:"lib64gstreamer1.0_0~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgst-gir1.0", rpm:"libgst-gir1.0~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-gir1.0", rpm:"libgstgl-gir1.0~1.22.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl1.0_0", rpm:"libgstgl1.0_0~1.22.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base-gir1.0", rpm:"libgstreamer-plugins-base-gir1.0~1.22.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base1.0-devel", rpm:"libgstreamer-plugins-base1.0-devel~1.22.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-plugins-base1.0_0", rpm:"libgstreamer-plugins-base1.0_0~1.22.11~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer1.0-devel", rpm:"libgstreamer1.0-devel~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer1.0_0", rpm:"libgstreamer1.0_0~1.22.11~1.1.mga9", rls:"MAGEIA9"))) {
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
