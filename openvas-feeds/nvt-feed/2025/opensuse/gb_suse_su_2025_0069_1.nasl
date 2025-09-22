# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856909");
  script_version("2025-02-20T08:47:14+0000");
  script_cve_id("CVE-2024-47538", "CVE-2024-47541", "CVE-2024-47542", "CVE-2024-47600", "CVE-2024-47607", "CVE-2024-47615", "CVE-2024-47835");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-20 08:47:14 +0000 (Thu, 20 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-18 19:57:16 +0000 (Wed, 18 Dec 2024)");
  script_tag(name:"creation_date", value:"2025-01-11 05:00:09 +0000 (Sat, 11 Jan 2025)");
  script_name("openSUSE: Security Advisory for gstreamer (SUSE-SU-2025:0069-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:0069-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BUKXU7D73HX7CQRDDBFEG7DOYTL345VF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer'
  package(s) announced via the SUSE-SU-2025:0069-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-plugins-base fixes the following issues:

  * CVE-2024-47538: Fixed a stack-buffer overflow in
      vorbis_handle_identification_packet. (bsc#1234415)

  * CVE-2024-47835: Fixed a NULL-pointer dereference in LRC subtitle parser.
      (bsc#1234450)

  * CVE-2024-47600: Fixed an out-of-bounds read in gst-discoverer-1.0
      commandline tool. (bsc#1234453)

  * CVE-2024-47615: Fixed an out-of-bounds write in Ogg demuxer. (bsc#1234456)

  * CVE-2024-47541: Fixed an out-of-bounds write in SSA subtitle parser.
      (bsc#1234459)

  * CVE-2024-47542: Fixed an ID3v2 parser out-of-bounds read and NULL-pointer
      dereference. (bsc#1234460)

  * CVE-2024-47607: Fixed a stack buffer-overflow in Opus decoder. (bsc#1234455)");

  script_tag(name:"affected", value:"'gstreamer' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base", rpm:"gstreamer-plugins-base~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-10-0-debuginfo", rpm:"libgstapp-10-0-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-10-0-debuginfo", rpm:"libgstvideo-10-0-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-GstApp-10", rpm:"typelib-10-GstApp-10~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-debugsource", rpm:"gstreamer-plugins-base-debugsource~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-10-0", rpm:"libgstriff-10-0~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-GstAudio-10", rpm:"typelib-10-GstAudio-10~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-10-0", rpm:"libgstfft-10-0~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-10-0-debuginfo", rpm:"libgstgl-10-0-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-10-0-debuginfo", rpm:"libgstrtsp-10-0-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-10-0", rpm:"libgstvideo-10-0~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-10-0", rpm:"libgstaudio-10-0~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-GstVideo-10", rpm:"typelib-10-GstVideo-10~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-10-0-debuginfo", rpm:"libgstsdp-10-0-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-10-0-debuginfo", rpm:"libgsttag-10-0-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-GstTag-10", rpm:"typelib-10-GstTag-10~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-10-0", rpm:"libgsttag-10-0~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-GstRtp-10", rpm:"typelib-10-GstRtp-10~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-10-0-debuginfo", rpm:"libgstallocators-10-0-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-GstPbutils-10", rpm:"typelib-10-GstPbutils-10~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-10-0", rpm:"libgstrtp-10-0~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-GstGL-10", rpm:"typelib-10-GstGL-10~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-10-0-debuginfo", rpm:"libgstriff-10-0-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-GstGLWayland-10", rpm:"typelib-10-GstGLWayland-10~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-10-0-debuginfo", rpm:"libgstrtp-10-0-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-10-0", rpm:"libgstrtsp-10-0~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-10-0", rpm:"libgstapp-10-0~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-debuginfo", rpm:"gstreamer-plugins-base-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-GstSdp-10", rpm:"typelib-10-GstSdp-10~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-10-0-debuginfo", rpm:"libgstfft-10-0-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-10-0-debuginfo", rpm:"libgstpbutils-10-0-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-devel", rpm:"gstreamer-plugins-base-devel~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-10-0", rpm:"libgstgl-10-0~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-10-0", rpm:"libgstpbutils-10-0~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-10-0-debuginfo", rpm:"libgstaudio-10-0-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-GstGLEGL-10", rpm:"typelib-10-GstGLEGL-10~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-GstAllocators-10", rpm:"typelib-10-GstAllocators-10~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-GstGLX11-10", rpm:"typelib-10-GstGLX11-10~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-10-GstRtsp-10", rpm:"typelib-10-GstRtsp-10~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-10-0", rpm:"libgstallocators-10-0~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-10-0", rpm:"libgstsdp-10-0~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-10-0-32bit-debuginfo", rpm:"libgstriff-10-0-32bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-10-0-32bit", rpm:"libgstapp-10-0-32bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-devel-32bit", rpm:"gstreamer-plugins-base-devel-32bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-10-0-32bit-debuginfo", rpm:"libgstapp-10-0-32bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-10-0-32bit-debuginfo", rpm:"libgstfft-10-0-32bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-10-0-32bit", rpm:"libgstallocators-10-0-32bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-10-0-32bit-debuginfo", rpm:"libgstgl-10-0-32bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-32bit-debuginfo", rpm:"gstreamer-plugins-base-32bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-10-0-32bit", rpm:"libgsttag-10-0-32bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-10-0-32bit", rpm:"libgstvideo-10-0-32bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-10-0-32bit-debuginfo", rpm:"libgstrtp-10-0-32bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-10-0-32bit-debuginfo", rpm:"libgstrtsp-10-0-32bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-10-0-32bit", rpm:"libgstrtsp-10-0-32bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-32bit", rpm:"gstreamer-plugins-base-32bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-10-0-32bit", rpm:"libgstrtp-10-0-32bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-10-0-32bit-debuginfo", rpm:"libgstvideo-10-0-32bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-10-0-32bit-debuginfo", rpm:"libgsttag-10-0-32bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-10-0-32bit", rpm:"libgstriff-10-0-32bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-10-0-32bit", rpm:"libgstaudio-10-0-32bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-10-0-32bit-debuginfo", rpm:"libgstallocators-10-0-32bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-10-0-32bit", rpm:"libgstfft-10-0-32bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-10-0-32bit", rpm:"libgstpbutils-10-0-32bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-10-0-32bit-debuginfo", rpm:"libgstpbutils-10-0-32bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-10-0-32bit-debuginfo", rpm:"libgstsdp-10-0-32bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-10-0-32bit", rpm:"libgstgl-10-0-32bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-10-0-32bit", rpm:"libgstsdp-10-0-32bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-10-0-32bit-debuginfo", rpm:"libgstaudio-10-0-32bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-lang", rpm:"gstreamer-plugins-base-lang~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-64bit", rpm:"gstreamer-plugins-base-64bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-10-0-64bit-debuginfo", rpm:"libgstapp-10-0-64bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-10-0-64bit", rpm:"libgstapp-10-0-64bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-10-0-64bit", rpm:"libgstfft-10-0-64bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-10-0-64bit-debuginfo", rpm:"libgstvideo-10-0-64bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-10-0-64bit", rpm:"libgstgl-10-0-64bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-64bit-debuginfo", rpm:"gstreamer-plugins-base-64bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-10-0-64bit-debuginfo", rpm:"libgstfft-10-0-64bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-10-0-64bit-debuginfo", rpm:"libgstrtsp-10-0-64bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-10-0-64bit-debuginfo", rpm:"libgstrtp-10-0-64bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-10-0-64bit", rpm:"libgstrtsp-10-0-64bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-10-0-64bit", rpm:"libgstaudio-10-0-64bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-10-0-64bit-debuginfo", rpm:"libgsttag-10-0-64bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-10-0-64bit-debuginfo", rpm:"libgstpbutils-10-0-64bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-10-0-64bit", rpm:"libgsttag-10-0-64bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-10-0-64bit", rpm:"libgstsdp-10-0-64bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-10-0-64bit", rpm:"libgstvideo-10-0-64bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-10-0-64bit", rpm:"libgstriff-10-0-64bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-devel-64bit", rpm:"gstreamer-plugins-base-devel-64bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-10-0-64bit-debuginfo", rpm:"libgstaudio-10-0-64bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-10-0-64bit-debuginfo", rpm:"libgstriff-10-0-64bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-10-0-64bit-debuginfo", rpm:"libgstallocators-10-0-64bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-10-0-64bit", rpm:"libgstallocators-10-0-64bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-10-0-64bit-debuginfo", rpm:"libgstsdp-10-0-64bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-10-0-64bit", rpm:"libgstrtp-10-0-64bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-10-0-64bit", rpm:"libgstpbutils-10-0-64bit~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-10-0-64bit-debuginfo", rpm:"libgstgl-10-0-64bit-debuginfo~1.20.1~150400.3.11.1", rls:"openSUSELeap15.4"))) {
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
