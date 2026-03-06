# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0762.1");
  script_cve_id("CVE-2026-22855", "CVE-2026-22857", "CVE-2026-23533", "CVE-2026-23732", "CVE-2026-23884", "CVE-2026-24491", "CVE-2026-24675", "CVE-2026-24676", "CVE-2026-24679", "CVE-2026-24682", "CVE-2026-24684");
  script_tag(name:"creation_date", value:"2026-03-05 04:35:46 +0000 (Thu, 05 Mar 2026)");
  script_version("2026-03-05T05:55:06+0000");
  script_tag(name:"last_modification", value:"2026-03-05 05:55:06 +0000 (Thu, 05 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-28 18:31:29 +0000 (Wed, 28 Jan 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0762-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0762-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260762-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257981");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257982");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257986");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257989");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257991");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024554.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the SUSE-SU-2026:0762-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freerdp fixes the following issues:

- CVE-2026-22855: heap-buffer-overflow in smartcard_unpack_set_attrib_call (bsc#1256721).
- CVE-2026-22857: heap-use-after-free in irp_thread_func (bsc#1256723).
- CVE-2026-23533: improper validation can lead to heap buffer overflow in `clear_decompress_residual_data`
 (bsc#1256943).
- CVE-2026-23732: improper validation can lead to heap buffer overflow in `Glyph_Alloc` (bsc#1256945).
- CVE-2026-23884: use-after-free in `gdi_set_bounds` (bsc#1256947).
- CVE-2026-24491: heap-use-after-free in video_timer (bsc#1257981).
- CVE-2026-24675: heap-use-after-free in urb_select_interface (bsc#1257982).
- CVE-2026-24676: heap-use-after-free in audio_format_compatible (bsc#1257983).
- CVE-2026-24679: heap-buffer-overflow in urb_select_interface (bsc#1257986).
- CVE-2026-24682: heap-buffer-overflow in audio_formats_free (bsc#1257989).
- CVE-2026-24684: heap-use-after-free in play_thread (bsc#1257991).");

  script_tag(name:"affected", value:"'freerdp' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.1.2~12.57.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"winpr2-devel", rpm:"winpr2-devel~2.1.2~12.57.1", rls:"SLES12.0SP5"))) {
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
