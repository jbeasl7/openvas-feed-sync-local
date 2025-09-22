# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1359.1");
  script_cve_id("CVE-2015-0295", "CVE-2015-1858", "CVE-2015-1859", "CVE-2015-1860");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1359-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1359-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151359-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/847880");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/921999");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927806");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927807");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929688");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-August/001528.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt4' package(s) announced via the SUSE-SU-2015:1359-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The libqt4 library was updated to fix several security and non security issues.

The following vulnerabilities were fixed:
- bsc#921999: CVE-2015-0295: division by zero when processing malformed BMP files
- bsc#927806: CVE-2015-1858: segmentation fault in BMP Qt Image Format Handling
- bsc#927807: CVE-2015-1859: segmentation fault in ICO Qt Image Format Handling
- bsc#927808: CVE-2015-1860: segmentation fault in GIF Qt Image Format Handling

The following non-security issues were fixed:
- bsc#929688: Critical Problem in Qt Network Stack
- bsc#847880: kde/qt rendering error in qemu cirrus i586
- Update use-freetype-default.diff to use same method as with
 libqt5-qtbase package: Qt itself already does runtime check
 whether subpixel rendering is available, but only when
 FT_CONFIG_OPTION_SUBPIXEL_RENDERING is defined. Thus it is enough
 to only remove that condition
- The -devel subpackage requires Mesa-devel, not only at build time
- Fixed compilation on SLE_11_SP3 by making it build against
 Mesa-devel on that system
- Replace patch l-qclipboard_fix_recursive.patch with
 qtcore-4.8.5-qeventdispatcher-recursive.patch. The later one
 seems to work better and really resolves the issue in LibreOffice
- Added kde4_qt_plugin_path.patch, so kde4 plugins are magically
 found/known outside kde4 enviroment/session
- added _constraints. building took up to 7GB of disk space on
 s390x, and more than 6GB on x86_64
- Add 3 patches for Qt bugs to make LibreOffice KDE4 file
 picker work properly again:
 * Add glib-honor-ExcludeSocketNotifiers-flag.diff (QTBUG-37380)
 * Add l-qclipboard_fix_recursive.patch (QTBUG-34614)
 * Add l-qclipboard_delay.patch (QTBUG-38585)");

  script_tag(name:"affected", value:"'libqt4' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP Applications 12.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libqt4-32bit", rpm:"libqt4-32bit~4.8.6~4.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4", rpm:"libqt4~4.8.6~4.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support-32bit", rpm:"libqt4-qt3support-32bit~4.8.6~4.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-qt3support", rpm:"libqt4-qt3support~4.8.6~4.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-32bit", rpm:"libqt4-sql-32bit~4.8.6~4.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql", rpm:"libqt4-sql~4.8.6~4.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-mysql", rpm:"libqt4-sql-mysql~4.8.6~4.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-sql-sqlite", rpm:"libqt4-sql-sqlite~4.8.6~4.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11-32bit", rpm:"libqt4-x11-32bit~4.8.6~4.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt4-x11", rpm:"libqt4-x11~4.8.6~4.2", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt4-x11-tools", rpm:"qt4-x11-tools~4.8.6~4.6", rls:"SLES12.0"))) {
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
