# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.2.2025.02954.1");
  script_cve_id("CVE-2025-6199", "CVE-2025-7345");
  script_tag(name:"creation_date", value:"2025-08-25 04:10:23 +0000 (Mon, 25 Aug 2025)");
  script_version("2025-08-25T05:40:31+0000");
  script_tag(name:"last_modification", value:"2025-08-25 05:40:31 +0000 (Mon, 25 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-07-08 14:15:32 +0000 (Tue, 08 Jul 2025)");

  script_name("openSUSE Security Advisory (SUSE-SU-2025:02954-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02954-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502954-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1245227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246114");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041329.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdk-pixbuf' package(s) announced via the SUSE-SU-2025:02954-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gdk-pixbuf fixes the following issues:

- CVE-2025-6199: Fixed uninitialized memory leading to arbitrary memory contents leak (bsc#1245227)
- CVE-2025-7345: Fixed heap buffer overflow within the gdk_pixbuf__jpeg_image_load_increment function (bsc#1246114)");

  script_tag(name:"affected", value:"'gdk-pixbuf' package(s) on openSUSE Leap 15.6.");

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

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel", rpm:"gdk-pixbuf-devel~2.42.12~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel-32bit", rpm:"gdk-pixbuf-devel-32bit~2.42.12~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-lang", rpm:"gdk-pixbuf-lang~2.42.12~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders", rpm:"gdk-pixbuf-query-loaders~2.42.12~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-32bit", rpm:"gdk-pixbuf-query-loaders-32bit~2.42.12~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-thumbnailer", rpm:"gdk-pixbuf-thumbnailer~2.42.12~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0", rpm:"libgdk_pixbuf-2_0-0~2.42.12~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-32bit", rpm:"libgdk_pixbuf-2_0-0-32bit~2.42.12~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GdkPixbuf-2_0", rpm:"typelib-1_0-GdkPixbuf-2_0~2.42.12~150600.3.8.1", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GdkPixdata-2_0", rpm:"typelib-1_0-GdkPixdata-2_0~2.42.12~150600.3.8.1", rls:"openSUSELeap15.6"))) {
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
