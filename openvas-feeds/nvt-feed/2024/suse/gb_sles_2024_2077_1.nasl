# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2077.1");
  script_cve_id("CVE-2022-48622");
  script_tag(name:"creation_date", value:"2024-06-19 12:06:28 +0000 (Wed, 19 Jun 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 15:53:45 +0000 (Fri, 02 Feb 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2077-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2077-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242077-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1195391");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1219276");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1223903");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2024-June/035643.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdk-pixbuf' package(s) announced via the SUSE-SU-2024:2077-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gdk-pixbuf fixes the following issues:

gdk-pixbuf was updated to version 2.42.12:

- Security issues fixed:

 * CVE-2022-48622: Fixed heap memory corruption on gdk-pixbuf (bsc#1219276)

- Changes in version 2.42.12:

 + ani: Reject files with multiple INA or IART chunks,
 + ani: validate chunk size,
 + Updated translations.

- Enable other image loaders such as xpm and xbm (bsc#1223903)

- Changes in version 2.42.11:

 + Disable fringe loaders by default.
 + Introspection fixes.
 + Updated translations.

- Changes in version 2.42.10:

 + Search for rst2man.py.
 + Update the memory size limit for JPEG images.
 + Updated translations.

- Fixed loading of larger images
- Avoid Bash specific syntax in baselibs postscript (bsc#1195391)");

  script_tag(name:"affected", value:"'gdk-pixbuf' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-devel", rpm:"gdk-pixbuf-devel~2.42.12~150400.5.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-lang", rpm:"gdk-pixbuf-lang~2.42.12~150400.5.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders", rpm:"gdk-pixbuf-query-loaders~2.42.12~150400.5.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-query-loaders-32bit", rpm:"gdk-pixbuf-query-loaders-32bit~2.42.12~150400.5.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdk-pixbuf-thumbnailer", rpm:"gdk-pixbuf-thumbnailer~2.42.12~150400.5.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0", rpm:"libgdk_pixbuf-2_0-0~2.42.12~150400.5.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgdk_pixbuf-2_0-0-32bit", rpm:"libgdk_pixbuf-2_0-0-32bit~2.42.12~150400.5.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GdkPixbuf-2_0", rpm:"typelib-1_0-GdkPixbuf-2_0~2.42.12~150400.5.9.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-GdkPixdata-2_0", rpm:"typelib-1_0-GdkPixdata-2_0~2.42.12~150400.5.9.1", rls:"SLES15.0SP4"))) {
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
