# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0046");
  script_cve_id("CVE-2026-23530", "CVE-2026-23531", "CVE-2026-23532", "CVE-2026-23533", "CVE-2026-23534", "CVE-2026-23948", "CVE-2026-24491", "CVE-2026-24675", "CVE-2026-24676", "CVE-2026-24677", "CVE-2026-24678", "CVE-2026-24679", "CVE-2026-24680", "CVE-2026-24681", "CVE-2026-24682", "CVE-2026-24683", "CVE-2026-24684");
  script_tag(name:"creation_date", value:"2026-02-23 04:46:17 +0000 (Mon, 23 Feb 2026)");
  script_version("2026-02-23T06:01:22+0000");
  script_tag(name:"last_modification", value:"2026-02-23 06:01:22 +0000 (Mon, 23 Feb 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-28 18:44:11 +0000 (Wed, 28 Jan 2026)");

  script_name("Mageia: Security Advisory (MGASA-2026-0046)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0046");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0046.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35038");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/3PECP75D65BGMOXX4VA6VFZW5A365UOB/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8004-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8042-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/02/09/8");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/02/10/1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the MGASA-2026-0046 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FreeRDP has heap-buffer-overflow in planar_decompress_plane_rle.
(CVE-2026-23530)
FreeRDP has heap-buffer-overflow in clear_decompress. (CVE-2026-23531)
FreeRDP has heap-buffer-overflow in gdi_SurfaceToSurface.
(CVE-2026-23532)
FreeRDP has heap-buffer-overflow in clear_decompress_residual_data.
(CVE-2026-23533)
FreeRDP has heap-buffer-overflow in clear_decompress_bands_data.
(CVE-2026-23534)
FreeRDP has a NULL Pointer Dereference in rdp_write_logon_info_v2().
(CVE-2026-23948)
FreeRDP has a heap-use-after-free in video_timer. (CVE-2026-24491)
FreeRDP has a Heap-use-after-free in urb_select_interface.
(CVE-2026-24675)
FreeRDP has a heap-use-after-free in audio_format_compatible.
(CVE-2026-24676)
FreeRDP has a heap-buffer-overflow in ecam_encoder_compress_h264.
(CVE-2026-24677)
FreeRDP has a Heap-use-after-free in cam_v4l_stream_capture_thread.
(CVE-2026-24678)
FreeRDP has a heap-buffer-overflow in urb_select_interface.
(CVE-2026-24679)
FreeRDP has a heap-use-after-free in update_pointer_new(SDL).
(CVE-2026-24680)
FreeRDP has a heap-use-after-free in urb_bulk_transfer_cb.
(CVE-2026-24681)
FreeRDP has a Heap-buffer-overflow in audio_formats_free.
(CVE-2026-24682)
FreeRDP has a heap-use-after-free in ainput_send_input_event.
(CVE-2026-24683)
FreeRDP has a Heap-use-after-free in play_thread. (CVE-2026-24684)");

  script_tag(name:"affected", value:"'freerdp' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.11.7~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp-devel", rpm:"lib64freerdp-devel~2.11.7~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp2", rpm:"lib64freerdp2~2.11.7~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp-devel", rpm:"libfreerdp-devel~2.11.7~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.11.7~1.2.mga9", rls:"MAGEIA9"))) {
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
