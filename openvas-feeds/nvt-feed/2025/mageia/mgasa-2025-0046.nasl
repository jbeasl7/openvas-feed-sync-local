# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2025.0046");
  script_cve_id("CVE-2023-51714", "CVE-2024-25580", "CVE-2024-39936");
  script_tag(name:"creation_date", value:"2025-02-10 04:12:04 +0000 (Mon, 10 Feb 2025)");
  script_version("2025-02-10T05:38:01+0000");
  script_tag(name:"last_modification", value:"2025-02-10 05:38:01 +0000 (Mon, 10 Feb 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-04 16:36:01 +0000 (Thu, 04 Jan 2024)");

  script_name("Mageia: Security Advisory (MGASA-2025-0046)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2025-0046");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2025-0046.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=33159");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/KVCBTKX6LVBTP6UEJQZ2PENI2KATSRJK/");
  script_xref(name:"URL", value:"https://lwn.net/Articles/971686/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qtbase5, qtbase6' package(s) announced via the MGASA-2025-0046 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"network/access/http2/hpacktable.cpp has an incorrect HPack integer
overflow check. (CVE-2023-51714)
A buffer overflow and application crash can occur via a crafted KTX
image file. (CVE-2024-25580)
Code to make security-relevant decisions about an established connection
may execute too early, because the encrypted() signal has not yet been
emitted and processed. (CVE-2024-39936)");

  script_tag(name:"affected", value:"'qtbase5, qtbase6' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-ibase", rpm:"lib64qt5-database-plugin-ibase~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-mysql", rpm:"lib64qt5-database-plugin-mysql~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-odbc", rpm:"lib64qt5-database-plugin-odbc~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-pgsql", rpm:"lib64qt5-database-plugin-pgsql~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-sqlite", rpm:"lib64qt5-database-plugin-sqlite~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5-database-plugin-tds", rpm:"lib64qt5-database-plugin-tds~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5accessibilitysupport-static-devel", rpm:"lib64qt5accessibilitysupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5base5-devel", rpm:"lib64qt5base5-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5bootstrap-static-devel", rpm:"lib64qt5bootstrap-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5concurrent-devel", rpm:"lib64qt5concurrent-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5concurrent5", rpm:"lib64qt5concurrent5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5core-devel", rpm:"lib64qt5core-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5core5", rpm:"lib64qt5core5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5dbus-devel", rpm:"lib64qt5dbus-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5dbus5", rpm:"lib64qt5dbus5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5devicediscoverysupport-static-devel", rpm:"lib64qt5devicediscoverysupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5edid-devel", rpm:"lib64qt5edid-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eglfsdeviceintegration-devel", rpm:"lib64qt5eglfsdeviceintegration-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eglfsdeviceintegration5", rpm:"lib64qt5eglfsdeviceintegration5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eglfskmssupport-devel", rpm:"lib64qt5eglfskmssupport-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eglfskmssupport5", rpm:"lib64qt5eglfskmssupport5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eglsupport-static-devel", rpm:"lib64qt5eglsupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5eventdispatchersupport-static-devel", rpm:"lib64qt5eventdispatchersupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5fbsupport-static-devel", rpm:"lib64qt5fbsupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5fontdatabasesupport-static-devel", rpm:"lib64qt5fontdatabasesupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5glxsupport-static-devel", rpm:"lib64qt5glxsupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5gui-devel", rpm:"lib64qt5gui-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5gui5", rpm:"lib64qt5gui5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5inputsupport-static-devel", rpm:"lib64qt5inputsupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5kmssupport-static-devel", rpm:"lib64qt5kmssupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5linuxaccessibilitysupport-static-devel", rpm:"lib64qt5linuxaccessibilitysupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5network-devel", rpm:"lib64qt5network-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5network5", rpm:"lib64qt5network5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5opengl-devel", rpm:"lib64qt5opengl-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5opengl5", rpm:"lib64qt5opengl5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5platformcompositorsupport-static-devel", rpm:"lib64qt5platformcompositorsupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5platformsupport-devel", rpm:"lib64qt5platformsupport-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5printsupport-devel", rpm:"lib64qt5printsupport-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5printsupport5", rpm:"lib64qt5printsupport5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5servicesupport-static-devel", rpm:"lib64qt5servicesupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5sql-devel", rpm:"lib64qt5sql-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5sql5", rpm:"lib64qt5sql5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5test-devel", rpm:"lib64qt5test-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5test5", rpm:"lib64qt5test5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5themesupport-static-devel", rpm:"lib64qt5themesupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5vulkansupport-static-devel", rpm:"lib64qt5vulkansupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5widgets-devel", rpm:"lib64qt5widgets-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5widgets5", rpm:"lib64qt5widgets5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5xcbqpa-devel", rpm:"lib64qt5xcbqpa-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5xcbqpa5", rpm:"lib64qt5xcbqpa5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5xkbcommonsupport-static-devel", rpm:"lib64qt5xkbcommonsupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5xml-devel", rpm:"lib64qt5xml-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt5xml5", rpm:"lib64qt5xml5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6-database-plugin-ibase", rpm:"lib64qt6-database-plugin-ibase~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6-database-plugin-mysql", rpm:"lib64qt6-database-plugin-mysql~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6-database-plugin-odbc", rpm:"lib64qt6-database-plugin-odbc~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6-database-plugin-pgsql", rpm:"lib64qt6-database-plugin-pgsql~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6-database-plugin-sqlite", rpm:"lib64qt6-database-plugin-sqlite~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6base6-devel", rpm:"lib64qt6base6-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6concurrent-devel", rpm:"lib64qt6concurrent-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6concurrent6", rpm:"lib64qt6concurrent6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6core-devel", rpm:"lib64qt6core-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6core6", rpm:"lib64qt6core6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6dbus-devel", rpm:"lib64qt6dbus-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6dbus6", rpm:"lib64qt6dbus6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6devicediscoverysupport-static-devel", rpm:"lib64qt6devicediscoverysupport-static-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6eglfsdeviceintegration-devel", rpm:"lib64qt6eglfsdeviceintegration-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6eglfsdeviceintegration6", rpm:"lib64qt6eglfsdeviceintegration6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6eglfskmsgbmsupport-devel", rpm:"lib64qt6eglfskmsgbmsupport-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6eglfskmsgbmsupport6", rpm:"lib64qt6eglfskmsgbmsupport6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6eglfskmssupport-devel", rpm:"lib64qt6eglfskmssupport-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6eglfskmssupport6", rpm:"lib64qt6eglfskmssupport6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6fbsupport-static-devel", rpm:"lib64qt6fbsupport-static-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6gui-devel", rpm:"lib64qt6gui-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6gui6", rpm:"lib64qt6gui6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6inputsupport-static-devel", rpm:"lib64qt6inputsupport-static-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6kmssupport-static-devel", rpm:"lib64qt6kmssupport-static-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6network-devel", rpm:"lib64qt6network-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6network6", rpm:"lib64qt6network6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6opengl-devel", rpm:"lib64qt6opengl-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6opengl6", rpm:"lib64qt6opengl6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6openglwidgets-devel", rpm:"lib64qt6openglwidgets-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6openglwidgets6", rpm:"lib64qt6openglwidgets6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6printsupport-devel", rpm:"lib64qt6printsupport-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6printsupport6", rpm:"lib64qt6printsupport6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6sql-devel", rpm:"lib64qt6sql-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6sql6", rpm:"lib64qt6sql6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6test-devel", rpm:"lib64qt6test-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6test6", rpm:"lib64qt6test6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6widgets-devel", rpm:"lib64qt6widgets-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6widgets6", rpm:"lib64qt6widgets6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6xcbqpa-devel", rpm:"lib64qt6xcbqpa-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6xcbqpa6", rpm:"lib64qt6xcbqpa6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6xml-devel", rpm:"lib64qt6xml-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64qt6xml6", rpm:"lib64qt6xml6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-ibase", rpm:"libqt5-database-plugin-ibase~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-mysql", rpm:"libqt5-database-plugin-mysql~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-odbc", rpm:"libqt5-database-plugin-odbc~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-pgsql", rpm:"libqt5-database-plugin-pgsql~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-sqlite", rpm:"libqt5-database-plugin-sqlite~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5-database-plugin-tds", rpm:"libqt5-database-plugin-tds~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5accessibilitysupport-static-devel", rpm:"libqt5accessibilitysupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5base5-devel", rpm:"libqt5base5-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5bootstrap-static-devel", rpm:"libqt5bootstrap-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5concurrent-devel", rpm:"libqt5concurrent-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5concurrent5", rpm:"libqt5concurrent5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5core-devel", rpm:"libqt5core-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5core5", rpm:"libqt5core5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5dbus-devel", rpm:"libqt5dbus-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5dbus5", rpm:"libqt5dbus5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5devicediscoverysupport-static-devel", rpm:"libqt5devicediscoverysupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5edid-devel", rpm:"libqt5edid-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eglfsdeviceintegration-devel", rpm:"libqt5eglfsdeviceintegration-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eglfsdeviceintegration5", rpm:"libqt5eglfsdeviceintegration5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eglfskmssupport-devel", rpm:"libqt5eglfskmssupport-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eglfskmssupport5", rpm:"libqt5eglfskmssupport5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eglsupport-static-devel", rpm:"libqt5eglsupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5eventdispatchersupport-static-devel", rpm:"libqt5eventdispatchersupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5fbsupport-static-devel", rpm:"libqt5fbsupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5fontdatabasesupport-static-devel", rpm:"libqt5fontdatabasesupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5glxsupport-static-devel", rpm:"libqt5glxsupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5gui-devel", rpm:"libqt5gui-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5gui5", rpm:"libqt5gui5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5inputsupport-static-devel", rpm:"libqt5inputsupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5kmssupport-static-devel", rpm:"libqt5kmssupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5linuxaccessibilitysupport-static-devel", rpm:"libqt5linuxaccessibilitysupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5network-devel", rpm:"libqt5network-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5network5", rpm:"libqt5network5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5opengl-devel", rpm:"libqt5opengl-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5opengl5", rpm:"libqt5opengl5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5platformcompositorsupport-static-devel", rpm:"libqt5platformcompositorsupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5platformsupport-devel", rpm:"libqt5platformsupport-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5printsupport-devel", rpm:"libqt5printsupport-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5printsupport5", rpm:"libqt5printsupport5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5servicesupport-static-devel", rpm:"libqt5servicesupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5sql-devel", rpm:"libqt5sql-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5sql5", rpm:"libqt5sql5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5test-devel", rpm:"libqt5test-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5test5", rpm:"libqt5test5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5themesupport-static-devel", rpm:"libqt5themesupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5vulkansupport-static-devel", rpm:"libqt5vulkansupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5widgets-devel", rpm:"libqt5widgets-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5widgets5", rpm:"libqt5widgets5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5xcbqpa-devel", rpm:"libqt5xcbqpa-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5xcbqpa5", rpm:"libqt5xcbqpa5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5xkbcommonsupport-static-devel", rpm:"libqt5xkbcommonsupport-static-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5xml-devel", rpm:"libqt5xml-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt5xml5", rpm:"libqt5xml5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6-database-plugin-ibase", rpm:"libqt6-database-plugin-ibase~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6-database-plugin-mysql", rpm:"libqt6-database-plugin-mysql~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6-database-plugin-odbc", rpm:"libqt6-database-plugin-odbc~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6-database-plugin-pgsql", rpm:"libqt6-database-plugin-pgsql~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6-database-plugin-sqlite", rpm:"libqt6-database-plugin-sqlite~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6base6-devel", rpm:"libqt6base6-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6concurrent-devel", rpm:"libqt6concurrent-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6concurrent6", rpm:"libqt6concurrent6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6core-devel", rpm:"libqt6core-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6core6", rpm:"libqt6core6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6dbus-devel", rpm:"libqt6dbus-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6dbus6", rpm:"libqt6dbus6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6devicediscoverysupport-static-devel", rpm:"libqt6devicediscoverysupport-static-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6eglfsdeviceintegration-devel", rpm:"libqt6eglfsdeviceintegration-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6eglfsdeviceintegration6", rpm:"libqt6eglfsdeviceintegration6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6eglfskmsgbmsupport-devel", rpm:"libqt6eglfskmsgbmsupport-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6eglfskmsgbmsupport6", rpm:"libqt6eglfskmsgbmsupport6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6eglfskmssupport-devel", rpm:"libqt6eglfskmssupport-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6eglfskmssupport6", rpm:"libqt6eglfskmssupport6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6fbsupport-static-devel", rpm:"libqt6fbsupport-static-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6gui-devel", rpm:"libqt6gui-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6gui6", rpm:"libqt6gui6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6inputsupport-static-devel", rpm:"libqt6inputsupport-static-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6kmssupport-static-devel", rpm:"libqt6kmssupport-static-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6network-devel", rpm:"libqt6network-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6network6", rpm:"libqt6network6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6opengl-devel", rpm:"libqt6opengl-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6opengl6", rpm:"libqt6opengl6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6openglwidgets-devel", rpm:"libqt6openglwidgets-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6openglwidgets6", rpm:"libqt6openglwidgets6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6printsupport-devel", rpm:"libqt6printsupport-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6printsupport6", rpm:"libqt6printsupport6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6sql-devel", rpm:"libqt6sql-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6sql6", rpm:"libqt6sql6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6test-devel", rpm:"libqt6test-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6test6", rpm:"libqt6test6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6widgets-devel", rpm:"libqt6widgets-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6widgets6", rpm:"libqt6widgets6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6xcbqpa-devel", rpm:"libqt6xcbqpa-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6xcbqpa6", rpm:"libqt6xcbqpa6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6xml-devel", rpm:"libqt6xml-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libqt6xml6", rpm:"libqt6xml6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase5", rpm:"qtbase5~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase5-common", rpm:"qtbase5-common~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase5-common-devel", rpm:"qtbase5-common-devel~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase5-doc", rpm:"qtbase5-doc~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase5-examples", rpm:"qtbase5-examples~5.15.7~6.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase6", rpm:"qtbase6~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase6-common", rpm:"qtbase6-common~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase6-common-devel", rpm:"qtbase6-common-devel~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase6-examples", rpm:"qtbase6-examples~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qtbase6-qtpaths", rpm:"qtbase6-qtpaths~6.4.1~5.1.mga9", rls:"MAGEIA9"))) {
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
