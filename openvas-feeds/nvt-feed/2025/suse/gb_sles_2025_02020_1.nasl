# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02020.1");
  script_cve_id("CVE-2024-47538", "CVE-2024-47541", "CVE-2024-47542", "CVE-2024-47600", "CVE-2024-47607", "CVE-2024-47615", "CVE-2024-47835", "CVE-2025-47806", "CVE-2025-47807", "CVE-2025-47808");
  script_tag(name:"creation_date", value:"2025-06-23 04:17:35 +0000 (Mon, 23 Jun 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-18 19:57:16 +0000 (Wed, 18 Dec 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02020-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02020-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502020-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234415");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234450");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234453");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234455");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234456");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234459");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1234460");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244404");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244407");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-June/040377.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-plugins-base' package(s) announced via the SUSE-SU-2025:02020-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-plugins-base fixes the following issues:

- CVE-2024-47538: Fixed stack-buffer overflow in vorbis_handle_identification_packet (bnc#1234415)
- CVE-2024-47600: Fixed out-of-bounds read in gst-discoverer-1.0 commandline tool (bnc#1234453)
- CVE-2024-47615: Fixed out-of-bounds write in Ogg demuxer (bnc#1234456)
- CVE-2024-47542: Fixed ID3v2 parser out-of-bounds read and NULL-pointer dereference (bnc#1234460)
- CVE-2024-47607: Fixed stack buffer-overflow in Opus decoder (bnc#1234455)
- CVE-2024-47835: Fixed NULL-pointer dereference in LRC subtitle parser (bnc#1234450)
- CVE-2024-47541: Fixed out-of-bounds write in SSA subtitle parser (bnc#1234459)
- CVE-2025-47808: Fixed NULL-pointer dereference in TMPlayer subtitle parser (boo#1244404)
- CVE-2025-47807: Fixed NULL-pointer dereference in SubRip subtitle parser (boo#1244403)
- CVE-2025-47806: Fixed Stack buffer overflow in SubRip subtitle parser (boo#1244407)");

  script_tag(name:"affected", value:"'gstreamer-plugins-base' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base", rpm:"gstreamer-plugins-base~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-devel", rpm:"gstreamer-plugins-base-devel~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-lang", rpm:"gstreamer-plugins-base-lang~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0", rpm:"libgstallocators-1_0-0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0", rpm:"libgstapp-1_0-0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0", rpm:"libgstaudio-1_0-0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0", rpm:"libgstfft-1_0-0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstgl-1_0-0", rpm:"libgstgl-1_0-0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0", rpm:"libgstpbutils-1_0-0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0", rpm:"libgstriff-1_0-0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0", rpm:"libgstrtp-1_0-0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0", rpm:"libgstrtsp-1_0-0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0", rpm:"libgstsdp-1_0-0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0", rpm:"libgsttag-1_0-0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0", rpm:"libgstvideo-1_0-0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstAllocators-1_0", rpm:"typelib-1_0-GstAllocators-1_0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstApp-1_0", rpm:"typelib-1_0-GstApp-1_0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstAudio-1_0", rpm:"typelib-1_0-GstAudio-1_0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstGL-1_0", rpm:"typelib-1_0-GstGL-1_0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstPbutils-1_0", rpm:"typelib-1_0-GstPbutils-1_0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstRtp-1_0", rpm:"typelib-1_0-GstRtp-1_0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstRtsp-1_0", rpm:"typelib-1_0-GstRtsp-1_0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstSdp-1_0", rpm:"typelib-1_0-GstSdp-1_0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstTag-1_0", rpm:"typelib-1_0-GstTag-1_0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GstVideo-1_0", rpm:"typelib-1_0-GstVideo-1_0~1.16.3~150200.4.19.1", rls:"SLES15.0SP3"))) {
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
