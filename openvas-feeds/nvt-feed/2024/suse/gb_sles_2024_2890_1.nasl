# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.2890.1");
  script_cve_id("CVE-2023-45935", "CVE-2023-51714", "CVE-2024-39936");
  script_tag(name:"creation_date", value:"2024-08-14 04:25:53 +0000 (Wed, 14 Aug 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-04 16:36:01 +0000 (Thu, 04 Jan 2024)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:2890-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2890-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20242890-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1218413");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1222120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227426");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1227513");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-August/019180.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libqt5-qtbase' package(s) announced via the SUSE-SU-2024:2890-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libqt5-qtbase fixes the following issues:

- CVE-2023-51714: Fixed an incorrect integer overflow check (bsc#1218413).
- CVE-2024-39936: Fixed information leakage due to process HTTP2 communication before encrypted() can be responded to (bsc#1227426)
- CVE-2023-45935: Fixed NULL pointer dereference in QXcbConnection::initializeAllAtoms() due to anomalous behavior from the X server (bsc#1222120)

Other fixes:
 - Add patch from upstream to fix a regression in the ODBC driver (bsc#1227513, QTBUG-112375)
 - Add upstream patch to fix a potential overflow in assemble_hpack_block()");

  script_tag(name:"affected", value:"'libqt5-qtbase' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"libQt5Concurrent-devel", rpm:"libQt5Concurrent-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Concurrent5", rpm:"libQt5Concurrent5~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Core-devel", rpm:"libQt5Core-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Core-private-headers-devel", rpm:"libQt5Core-private-headers-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Core5", rpm:"libQt5Core5~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5DBus-devel", rpm:"libQt5DBus-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5DBus-private-headers-devel", rpm:"libQt5DBus-private-headers-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5DBus5", rpm:"libQt5DBus5~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Gui-devel", rpm:"libQt5Gui-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Gui-private-headers-devel", rpm:"libQt5Gui-private-headers-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Gui5", rpm:"libQt5Gui5~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5KmsSupport-devel-static", rpm:"libQt5KmsSupport-devel-static~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5KmsSupport-private-headers-devel", rpm:"libQt5KmsSupport-private-headers-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Network-devel", rpm:"libQt5Network-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Network-private-headers-devel", rpm:"libQt5Network-private-headers-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Network5", rpm:"libQt5Network5~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5OpenGL-devel", rpm:"libQt5OpenGL-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5OpenGL-private-headers-devel", rpm:"libQt5OpenGL-private-headers-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5OpenGL5", rpm:"libQt5OpenGL5~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5OpenGLExtensions-devel-static", rpm:"libQt5OpenGLExtensions-devel-static~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PlatformHeaders-devel", rpm:"libQt5PlatformHeaders-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PlatformSupport-devel-static", rpm:"libQt5PlatformSupport-devel-static~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PlatformSupport-private-headers-devel", rpm:"libQt5PlatformSupport-private-headers-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PrintSupport-devel", rpm:"libQt5PrintSupport-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PrintSupport-private-headers-devel", rpm:"libQt5PrintSupport-private-headers-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5PrintSupport5", rpm:"libQt5PrintSupport5~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql-devel", rpm:"libQt5Sql-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql-private-headers-devel", rpm:"libQt5Sql-private-headers-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5", rpm:"libQt5Sql5~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-mysql", rpm:"libQt5Sql5-mysql~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-postgresql", rpm:"libQt5Sql5-postgresql~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-sqlite", rpm:"libQt5Sql5-sqlite~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Sql5-unixODBC", rpm:"libQt5Sql5-unixODBC~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Test-devel", rpm:"libQt5Test-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Test-private-headers-devel", rpm:"libQt5Test-private-headers-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Test5", rpm:"libQt5Test5~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Widgets-devel", rpm:"libQt5Widgets-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Widgets-private-headers-devel", rpm:"libQt5Widgets-private-headers-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Widgets5", rpm:"libQt5Widgets5~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Xml-devel", rpm:"libQt5Xml-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt5Xml5", rpm:"libQt5Xml5~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-common-devel", rpm:"libqt5-qtbase-common-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-devel", rpm:"libqt5-qtbase-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-platformtheme-gtk3", rpm:"libqt5-qtbase-platformtheme-gtk3~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-qtbase-private-headers-devel", rpm:"libqt5-qtbase-private-headers-devel~5.15.2+kde294~150400.6.15.1", rls:"SLES15.0SP4"))) {
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
