# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856336");
  script_cve_id("CVE-2024-22211", "CVE-2024-32658", "CVE-2024-32659", "CVE-2024-32660", "CVE-2024-32661");
  script_tag(name:"creation_date", value:"2024-07-31 04:00:26 +0000 (Wed, 31 Jul 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-04 17:42:16 +0000 (Tue, 04 Feb 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2024:2631-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2631-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242631-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219049");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223346");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223348");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223353");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-July/019043.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the SUSE-SU-2024:2631-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for freerdp fixes the following issues:

- CVE-2024-22211: Fixed integer overflow in `freerdp_bitmap_planar_context_reset` that could lead to heap-buffer overflow (bsc#1219049)
- CVE-2024-32658: Fixed out-of-bounds read in Interleaved RLE Bitmap Codec in FreeRDP based clients (bsc#1223353)
- CVE-2024-32659: Fixed out-of-bounds read if `((nWidth == 0) and (nHeight == 0))` (bsc#1223346)
- CVE-2024-32660: Fixed client crash via invalid huge allocation size (bsc#1223347)
- CVE-2024-32661: Fixed client NULL pointer dereference (bsc#1223348)");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.11.2~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.11.2~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-proxy", rpm:"freerdp-proxy~2.11.2~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server", rpm:"freerdp-server~2.11.2~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-wayland", rpm:"freerdp-wayland~2.11.2~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfreerdp2-2", rpm:"libfreerdp2-2~2.11.2~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuwac0-0", rpm:"libuwac0-0~2.11.2~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr2-2", rpm:"libwinpr2-2~2.11.2~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uwac0-0-devel", rpm:"uwac0-0-devel~2.11.2~150600.4.3.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"winpr-devel", rpm:"winpr-devel~2.11.2~150600.4.3.1", rls:"openSUSELeap15.6"))) {
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
