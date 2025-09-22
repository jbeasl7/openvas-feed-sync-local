# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833508");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-32762", "CVE-2023-32763", "CVE-2023-33285", "CVE-2023-34410", "CVE-2023-38197");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-25 14:10:05 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:36:12 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for qt6 (SUSE-SU-2023:3380-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:3380-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/7X6B3DORGRR3LY4BZXJIYARESOKTIVK5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt6'
  package(s) announced via the SUSE-SU-2023:3380-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qt6-base fixes the following issues:

  * CVE-2023-34410: Fixed certificate validation flaw (bsc#1211994).

  * CVE-2023-33285: Fixed buffer overflow in QDnsLookup (bsc#1211642).

  * CVE-2023-32762: Fixed strict-transport-security (HSTS) header parsing error
      (QTBUG-113392) (bsc#1211797).

  * CVE-2023-38197: Fixed infinite loops in QXmlStreamReader (QTBUG-92113,
      QTBUG-95188) (bsc#1213326).

  * CVE-2023-32763: Fixed buffer overflow in QTextLayout (QTBUG-113337,
      QTBUG-106947, QTBUG-89557, QTBUG-104986) (bsc#1211798).

  ##");

  script_tag(name:"affected", value:"'qt6' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"qt6-networkinformation-nm", rpm:"qt6-networkinformation-nm~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Gui6", rpm:"libQt6Gui6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Core6", rpm:"libQt6Core6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformtheme-xdgdesktopportal-debuginfo", rpm:"qt6-platformtheme-xdgdesktopportal-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Test6", rpm:"libQt6Test6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6OpenGLWidgets6-debuginfo", rpm:"libQt6OpenGLWidgets6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6PrintSupport6", rpm:"libQt6PrintSupport6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-kmssupport-private-devel", rpm:"qt6-kmssupport-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-core-private-devel", rpm:"qt6-core-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-printsupport-cups", rpm:"qt6-printsupport-cups~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-network-devel", rpm:"qt6-network-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-xml-private-devel", rpm:"qt6-xml-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-openglwidgets-devel", rpm:"qt6-openglwidgets-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformsupport-devel-static", rpm:"qt6-platformsupport-devel-static~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Network6-debuginfo", rpm:"libQt6Network6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-core-devel", rpm:"qt6-core-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-sqlite", rpm:"qt6-sql-sqlite~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-sqlite-debuginfo", rpm:"qt6-sql-sqlite-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformtheme-gtk3-debuginfo", rpm:"qt6-platformtheme-gtk3-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Sql6-debuginfo", rpm:"libQt6Sql6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-dbus-devel", rpm:"qt6-dbus-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Concurrent6", rpm:"libQt6Concurrent6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Core6-debuginfo", rpm:"libQt6Core6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Gui6-debuginfo", rpm:"libQt6Gui6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-gui-private-devel", rpm:"qt6-gui-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-widgets-devel", rpm:"qt6-widgets-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformtheme-xdgdesktopportal", rpm:"qt6-platformtheme-xdgdesktopportal~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-network-private-devel", rpm:"qt6-network-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-network-tls-debuginfo", rpm:"qt6-network-tls-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6PrintSupport6-debuginfo", rpm:"libQt6PrintSupport6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-opengl-devel", rpm:"qt6-opengl-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Network6", rpm:"libQt6Network6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-test-private-devel", rpm:"qt6-test-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Concurrent6-debuginfo", rpm:"libQt6Concurrent6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-printsupport-cups-debuginfo", rpm:"qt6-printsupport-cups-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6OpenGL6-debuginfo", rpm:"libQt6OpenGL6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Xml6", rpm:"libQt6Xml6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Sql6", rpm:"libQt6Sql6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-concurrent-devel", rpm:"qt6-concurrent-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Xml6-debuginfo", rpm:"libQt6Xml6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6OpenGL6", rpm:"libQt6OpenGL6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-common-devel-debuginfo", rpm:"qt6-base-common-devel-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-unixODBC", rpm:"qt6-sql-unixODBC~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6OpenGLWidgets6", rpm:"libQt6OpenGLWidgets6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-common-devel", rpm:"qt6-base-common-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-mysql-debuginfo", rpm:"qt6-sql-mysql-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-docs-qch", rpm:"qt6-base-docs-qch~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-networkinformation-nm-debuginfo", rpm:"qt6-networkinformation-nm-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-unixODBC-debuginfo", rpm:"qt6-sql-unixODBC-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-xml-devel", rpm:"qt6-xml-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-devel", rpm:"qt6-sql-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-printsupport-private-devel", rpm:"qt6-printsupport-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-private-devel", rpm:"qt6-sql-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6DBus6-debuginfo", rpm:"libQt6DBus6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6DBus6", rpm:"libQt6DBus6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-opengl-private-devel", rpm:"qt6-opengl-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-kmssupport-devel-static", rpm:"qt6-kmssupport-devel-static~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformtheme-gtk3", rpm:"qt6-platformtheme-gtk3~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-debuginfo", rpm:"qt6-base-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-examples", rpm:"qt6-base-examples~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-gui-devel", rpm:"qt6-gui-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-postgresql", rpm:"qt6-sql-postgresql~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-postgresql-debuginfo", rpm:"qt6-sql-postgresql-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-network-tls", rpm:"qt6-network-tls~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-test-devel", rpm:"qt6-test-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Widgets6-debuginfo", rpm:"libQt6Widgets6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Widgets6", rpm:"libQt6Widgets6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-docs-html", rpm:"qt6-base-docs-html~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-debugsource", rpm:"qt6-base-debugsource~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-widgets-private-devel", rpm:"qt6-widgets-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Test6-debuginfo", rpm:"libQt6Test6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformsupport-private-devel", rpm:"qt6-platformsupport-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-dbus-private-devel", rpm:"qt6-dbus-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-examples-debuginfo", rpm:"qt6-base-examples-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-mysql", rpm:"qt6-sql-mysql~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-printsupport-devel", rpm:"qt6-printsupport-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-devel", rpm:"qt6-base-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-docs-common", rpm:"qt6-docs-common~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-private-devel", rpm:"qt6-base-private-devel~6.2.2~150400.4.6.1##", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-networkinformation-nm", rpm:"qt6-networkinformation-nm~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Gui6", rpm:"libQt6Gui6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Core6", rpm:"libQt6Core6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformtheme-xdgdesktopportal-debuginfo", rpm:"qt6-platformtheme-xdgdesktopportal-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Test6", rpm:"libQt6Test6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6OpenGLWidgets6-debuginfo", rpm:"libQt6OpenGLWidgets6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6PrintSupport6", rpm:"libQt6PrintSupport6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-kmssupport-private-devel", rpm:"qt6-kmssupport-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-core-private-devel", rpm:"qt6-core-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-printsupport-cups", rpm:"qt6-printsupport-cups~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-network-devel", rpm:"qt6-network-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-xml-private-devel", rpm:"qt6-xml-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-openglwidgets-devel", rpm:"qt6-openglwidgets-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformsupport-devel-static", rpm:"qt6-platformsupport-devel-static~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Network6-debuginfo", rpm:"libQt6Network6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-core-devel", rpm:"qt6-core-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-sqlite", rpm:"qt6-sql-sqlite~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-sqlite-debuginfo", rpm:"qt6-sql-sqlite-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformtheme-gtk3-debuginfo", rpm:"qt6-platformtheme-gtk3-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Sql6-debuginfo", rpm:"libQt6Sql6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-dbus-devel", rpm:"qt6-dbus-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Concurrent6", rpm:"libQt6Concurrent6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Core6-debuginfo", rpm:"libQt6Core6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Gui6-debuginfo", rpm:"libQt6Gui6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-gui-private-devel", rpm:"qt6-gui-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-widgets-devel", rpm:"qt6-widgets-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformtheme-xdgdesktopportal", rpm:"qt6-platformtheme-xdgdesktopportal~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-network-private-devel", rpm:"qt6-network-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-network-tls-debuginfo", rpm:"qt6-network-tls-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6PrintSupport6-debuginfo", rpm:"libQt6PrintSupport6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-opengl-devel", rpm:"qt6-opengl-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Network6", rpm:"libQt6Network6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-test-private-devel", rpm:"qt6-test-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Concurrent6-debuginfo", rpm:"libQt6Concurrent6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-printsupport-cups-debuginfo", rpm:"qt6-printsupport-cups-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6OpenGL6-debuginfo", rpm:"libQt6OpenGL6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Xml6", rpm:"libQt6Xml6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Sql6", rpm:"libQt6Sql6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-concurrent-devel", rpm:"qt6-concurrent-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Xml6-debuginfo", rpm:"libQt6Xml6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6OpenGL6", rpm:"libQt6OpenGL6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-common-devel-debuginfo", rpm:"qt6-base-common-devel-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-unixODBC", rpm:"qt6-sql-unixODBC~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6OpenGLWidgets6", rpm:"libQt6OpenGLWidgets6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-common-devel", rpm:"qt6-base-common-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-mysql-debuginfo", rpm:"qt6-sql-mysql-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-docs-qch", rpm:"qt6-base-docs-qch~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-networkinformation-nm-debuginfo", rpm:"qt6-networkinformation-nm-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-unixODBC-debuginfo", rpm:"qt6-sql-unixODBC-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-xml-devel", rpm:"qt6-xml-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-devel", rpm:"qt6-sql-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-printsupport-private-devel", rpm:"qt6-printsupport-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-private-devel", rpm:"qt6-sql-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6DBus6-debuginfo", rpm:"libQt6DBus6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6DBus6", rpm:"libQt6DBus6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-opengl-private-devel", rpm:"qt6-opengl-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-kmssupport-devel-static", rpm:"qt6-kmssupport-devel-static~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformtheme-gtk3", rpm:"qt6-platformtheme-gtk3~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-debuginfo", rpm:"qt6-base-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-examples", rpm:"qt6-base-examples~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-gui-devel", rpm:"qt6-gui-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-postgresql", rpm:"qt6-sql-postgresql~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-postgresql-debuginfo", rpm:"qt6-sql-postgresql-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-network-tls", rpm:"qt6-network-tls~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-test-devel", rpm:"qt6-test-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Widgets6-debuginfo", rpm:"libQt6Widgets6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Widgets6", rpm:"libQt6Widgets6~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-docs-html", rpm:"qt6-base-docs-html~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-debugsource", rpm:"qt6-base-debugsource~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-widgets-private-devel", rpm:"qt6-widgets-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libQt6Test6-debuginfo", rpm:"libQt6Test6-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-platformsupport-private-devel", rpm:"qt6-platformsupport-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-dbus-private-devel", rpm:"qt6-dbus-private-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-examples-debuginfo", rpm:"qt6-base-examples-debuginfo~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-sql-mysql", rpm:"qt6-sql-mysql~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-printsupport-devel", rpm:"qt6-printsupport-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-devel", rpm:"qt6-base-devel~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-docs-common", rpm:"qt6-docs-common~6.2.2~150400.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qt6-base-private-devel", rpm:"qt6-base-private-devel~6.2.2~150400.4.6.1##", rls:"openSUSELeap15.4"))) {
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