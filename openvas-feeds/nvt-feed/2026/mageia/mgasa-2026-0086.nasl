# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0086");
  script_cve_id("CVE-2026-22852", "CVE-2026-22854", "CVE-2026-22855", "CVE-2026-22856", "CVE-2026-22857", "CVE-2026-22859", "CVE-2026-23732", "CVE-2026-23883", "CVE-2026-23884", "CVE-2026-24491", "CVE-2026-26271", "CVE-2026-26955", "CVE-2026-26965", "CVE-2026-31806", "CVE-2026-31883", "CVE-2026-31885");
  script_tag(name:"creation_date", value:"2026-04-07 04:51:37 +0000 (Tue, 07 Apr 2026)");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-17 14:26:13 +0000 (Tue, 17 Mar 2026)");

  script_name("Mageia: Security Advisory (MGASA-2026-0086)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0086");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0086.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35141");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/HAYMD62GFPCFHGN6JPLMCVJHP3SKINMW/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/J3QGQZQS6664TXPPYGBP7673W2JAXG4K/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/34ABPSLQFVRGFKDSR5ZEDKG5UH6KIBCA/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/message/F2VLQU7USVAQ733RYB7II6KGZB3FG2KW/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the MGASA-2026-0086 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"FreeRDP has a heap-buffer-overflow in audin_process_formats.
(CVE-2026-22852)
FreeRDP has a heap-buffer-overflow in drive_process_irp_read.
(CVE-2026-22854)
FreeRDP has a heap-buffer-overflow in smartcard_unpack_set_attrib_call.
(CVE-2026-22855)
FreeRDP has a heap-use-after-free in create_irp_thread. (CVE-2026-22856)
FreeRDP has a heap-use-after-free in irp_thread_func. (CVE-2026-22857)
FreeRDP has a heap-buffer-overflow in urb_select_configuration.
(CVE-2026-22859)
FreeRDP has heap-buffer-overflow in Glyph_Alloc. (CVE-2026-23732)
Heap-use-after-free in update_pointer_new. (CVE-2026-23883)
Heap-use-after-free in gdi_set_bounds. (CVE-2026-23884)
FreeRDP has a heap-use-after-free in video_timer. (CVE-2026-24491)
Buffer Overread in FreeRDP Icon Processing. (CVE-2026-26271)
FreeRDP has Out-of-bounds Write. (CVE-2026-26955, CVE-2026-26965)
FreeRDP has a Heap Buffer Overflow in nsc_process_message() via
Unchecked SURFACE_BITS_COMMAND Bitmap Dimensions. (CVE-2026-31806)
FreeRDP has a `size_t` underflow in ADPCM decoder leads to
heap-buffer-overflow write. (CVE-2026-31883)
FreeRDP has an out-of-bounds read in ADPCM decoders due to missing
predictor/step_index bounds checks. (CVE-2026-31885)");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.11.7~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp-devel", rpm:"lib64freerdp-devel~2.11.7~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64freerdp2", rpm:"lib64freerdp2~2.11.7~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp-devel", rpm:"libfreerdp-devel~2.11.7~1.3.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2", rpm:"libfreerdp2~2.11.7~1.3.mga9", rls:"MAGEIA9"))) {
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
