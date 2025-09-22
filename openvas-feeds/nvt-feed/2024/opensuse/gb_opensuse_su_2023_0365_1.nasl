# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833555");
  script_version("2025-08-14T05:40:53+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-37434", "CVE-2023-5217");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-14 05:40:53 +0000 (Thu, 14 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-11 18:38:23 +0000 (Thu, 11 Aug 2022)");
  script_tag(name:"creation_date", value:"2024-03-04 08:00:35 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for vlc (openSUSE-SU-2023:0365-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSEBackportsSLE-15-SP4");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2023:0365-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/4PHTZYGRNV6PDZMHUALPCK2YD6IRL3XD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vlc'
  package(s) announced via the openSUSE-SU-2023:0365-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for vlc fixes the following issues:

     Update to version 3.0.20:

     + Video Output:

  - Fix green line in fullscreen in D3D11 video output

  - Fix crash with some AMD drivers old versions

  - Fix events propagation issue when double-clicking with mouse wheel
     + Decoders:

  - Fix crash when AV1 hardware decoder fails
     + Interface:

  - Fix annoying disappearance of the Windows fullscreen controller
     + Demuxers:

  - Fix potential security issue (OOB Write) on MMS:// by checking user
         size bounds

     Update to version 3.0.19:

     + Core:

  - Fix next-frame freezing in most scenarios
     + Demux:

  - Support RIFF INFO tags for Wav files

  - Fix AVI files with flipped RAW video planes

  - Fix duration on short and small Ogg/Opus files

  - Fix some HLS/TS streams with ID3 prefix

  - Fix some HLS playlist refresh drift

  - Fix for GoPro MAX spatial metadata

  - Improve FFmpeg-muxed MP4 chapters handling

  - Improve playback for QNap-produced AVI files

  - Improve playback of some old RealVideo files

  - Fix duration probing on some MP4 with missing information
     + Decoders:

  - Multiple fixes on AAC handling

  - Activate hardware decoding of AV1 on Windows (DxVA)

  - Improve AV1 HDR support with software decoding

  - Fix some AV1 GBRP streams, AV1 super-resolution streams and monochrome
         ones

  - Fix black screen on poorly edited MP4 files on Android Mediacodec

  - Fix rawvid video in NV12

  - Fix several issues on Windows hardware decoding (including 'too large
         resolution in DxVA')

  - Improve crunchyroll-produced SSA rendering
     + Video Output:

  - Super Resolution scaling with nVidia and Intel GPUs

  - Fix for an issue when cropping on Direct3D9

  - Multiple fixes for hardware decoding on D3D11 and OpenGL interop

  - Fix an issue when playing -90°rotated video

  - Fix subtitles rendering blur on recent macOS
     + Input:

  - Improve SMB compatibility with Windows 11 hosts
     + Contribs:

  - Update of fluidlite, fixing some MIDI rendering on Windows

  - Update of zlib to 1.2.13 (CVE-2022-37434)

  - Update of FFmpeg, vpx (CVE-2023-5217), ebml, dav1d, libass
     + Misc:

  - Improve muxing timestamps in a few formats (reset to 0)

  - Fix some rendering issues on Linux with the fullscreen controller

  - Fix GOOM visualization

  - Fixes for Youtube playback

  - Fix some MPRIS inconsistencies that broke some OS widgets on Linu ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'vlc' package(s) on openSUSE Backports SLE-15-SP4.");

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

if(release == "openSUSEBackportsSLE-15-SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libvlc5", rpm:"libvlc5~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore9", rpm:"libvlccore9~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc", rpm:"vlc~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-codec-gstreamer", rpm:"vlc-codec-gstreamer~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-devel", rpm:"vlc-devel~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-jack", rpm:"vlc-jack~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-noX", rpm:"vlc-noX~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-opencv", rpm:"vlc-opencv~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-qt", rpm:"vlc-qt~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-vdpau", rpm:"vlc-vdpau~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-lang", rpm:"vlc-lang~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlc5", rpm:"libvlc5~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvlccore9", rpm:"libvlccore9~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc", rpm:"vlc~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-codec-gstreamer", rpm:"vlc-codec-gstreamer~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-devel", rpm:"vlc-devel~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-jack", rpm:"vlc-jack~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-noX", rpm:"vlc-noX~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-opencv", rpm:"vlc-opencv~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-qt", rpm:"vlc-qt~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-vdpau", rpm:"vlc-vdpau~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vlc-lang", rpm:"vlc-lang~3.0.20~bp154.2.6.1", rls:"openSUSEBackportsSLE-15-SP4"))) {
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