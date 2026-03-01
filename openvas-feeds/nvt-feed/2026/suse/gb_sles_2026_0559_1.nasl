# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0559.1");
  script_cve_id("CVE-2026-22852", "CVE-2026-22854", "CVE-2026-22856", "CVE-2026-22859", "CVE-2026-23530", "CVE-2026-23531", "CVE-2026-23532", "CVE-2026-23534");
  script_tag(name:"creation_date", value:"2026-02-17 14:15:11 +0000 (Tue, 17 Feb 2026)");
  script_version("2026-02-18T05:57:21+0000");
  script_tag(name:"last_modification", value:"2026-02-18 05:57:21 +0000 (Wed, 18 Feb 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-28 18:44:11 +0000 (Wed, 28 Jan 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0559-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0559-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260559-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256720");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256722");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256725");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256940");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256941");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256942");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256944");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024272.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the SUSE-SU-2026:0559-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freerdp fixes the following issues:

- CVE-2026-22852: a malicious RDP server can trigger a heap-buffer-overflow in audin_process_formats (bsc#1256718).
- CVE-2026-22854: server-controlled read length is used to read file data into an IRP output can cause
 heap-buffer-overflow in drive_process_irp_read (bsc#1256720).
- CVE-2026-22856: race condition in the serial channel IRP thread tracking can cause heap-use-after-free
 in create_irp_thread(bsc#1256722).
- CVE-2026-22859: improper bound check can lead to heap-buffer-overflow in urb_select_configuration (bsc#1256725).
- CVE-2026-23530: improper validation can lead to heap buffer overflow in `planar_decompress_plane_rle` (bsc#1256940).
- CVE-2026-23531: improper validation in `clear_decompress` can lead to heap buffer overflow (bsc#1256941).
- CVE-2026-23532: mismatch between destination rectangle clamping and the actual copy size can lead to a heap buffer
 overflow in `gdi_SurfaceToSurface` (bsc#1256942).
- CVE-2026-23534: missing checks can lead to heap buffer overflow in `clear_decompress_bands_data` (bsc#1256944).");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.1.2~12.52.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"winpr2-devel", rpm:"winpr2-devel~2.1.2~12.52.1", rls:"SLES12.0SP5"))) {
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
