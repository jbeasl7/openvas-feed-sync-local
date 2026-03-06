# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2026.0761.1");
  script_cve_id("CVE-2026-22855", "CVE-2026-22857", "CVE-2026-23533", "CVE-2026-23732", "CVE-2026-23883", "CVE-2026-23884");
  script_tag(name:"creation_date", value:"2026-03-05 04:35:07 +0000 (Thu, 05 Mar 2026)");
  script_version("2026-03-05T05:55:06+0000");
  script_tag(name:"last_modification", value:"2026-03-05 05:55:06 +0000 (Thu, 05 Mar 2026)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-28 18:31:29 +0000 (Wed, 28 Jan 2026)");

  script_name("openSUSE Security Advisory (SUSE-SU-2026:0761-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0761-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260761-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256721");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256723");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256943");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256947");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024555.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the SUSE-SU-2026:0761-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freerdp fixes the following issues:

- CVE-2026-22855: heap-buffer-overflow in smartcard_unpack_set_attrib_call (bsc#1256721).
- CVE-2026-22857: heap-use-after-free in irp_thread_func (bsc#1256723).
- CVE-2026-23533: improper validation can lead to heap buffer overflow in `clear_decompress_residual_data`
 (bsc#1256943).
- CVE-2026-23732: improper validation can lead to heap buffer overflow in `Glyph_Alloc` (bsc#1256945).
- CVE-2026-23883: use-after-free when `update_pointer_color` and `freerdp_image_copy_from_pointer_data` fail
 (bsc#1256946).
- CVE-2026-23884: use-after-free in `gdi_set_bounds` (bsc#1256947).");

  script_tag(name:"affected", value:"'freerdp' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.11.2~150600.4.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.11.2~150600.4.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy", rpm:"freerdp-proxy~2.11.2~150600.4.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server", rpm:"freerdp-server~2.11.2~150600.4.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-wayland", rpm:"freerdp-wayland~2.11.2~150600.4.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2-2", rpm:"libfreerdp2-2~2.11.2~150600.4.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuwac0-0", rpm:"libuwac0-0~2.11.2~150600.4.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2-2", rpm:"libwinpr2-2~2.11.2~150600.4.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwac0-0-devel", rpm:"uwac0-0-devel~2.11.2~150600.4.12.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"winpr-devel", rpm:"winpr-devel~2.11.2~150600.4.12.1", rls:"openSUSELeap15.6"))) {
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
