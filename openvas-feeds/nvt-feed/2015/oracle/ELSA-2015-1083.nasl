# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123105");
  script_cve_id("CVE-2015-1869", "CVE-2015-1870", "CVE-2015-3142", "CVE-2015-3147", "CVE-2015-3150", "CVE-2015-3151", "CVE-2015-3159", "CVE-2015-3315");
  script_tag(name:"creation_date", value:"2015-10-06 10:59:26 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-19 02:29:00 +0000 (Mon, 19 Feb 2018)");

  script_name("Oracle: Security Advisory (ELSA-2015-1083)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1083");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1083.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'abrt, libreport' package(s) announced via the ELSA-2015-1083 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"abrt
[2.1.11-22.0.1]
- Drop libreport-rhel and libreport-plugin-rhtsupport requires

[2.1.11-22]
- do not open the build_ids file as the user abrt
- do not unlink failed and big user core files
- Related: #1212819, #1216973

[2.1.11-21]
- validate all D-Bus method arguments
- Related: #1214610

[2.1.11-20]
- remove the old dump directories during upgrade
- abrt-action-install-debuginfo-to-abrt-cache: sanitize arguments and umask
- fix race conditions and directory traversal issues in abrt-dbus
- use /var/spool/abrt instead of /var/tmp/abrt
- make the problem directories owned by root and the group abrt
- validate uploaded problem directories in abrt-handle-upload
- don't override files with user core dump files
- fix symbolic link and race condition flaws
- Resolves: #1211969, #1212819, #1212863, #1212869
- Resolves: #1214453, #1214610, #1216973, #1218583

libreport
[2.1.11-23.0.1]
- Update workflow xml for Oracle [18945470]
- Add oracle-enterprise.patch and oracle-enterprise-po.patch
- Remove libreport-plugin-rhtsupport and libreport-rhel
- Added orabug20390725.patch to remove redhat reference [bug 20390725]
- Added Bug20357383.patch to remove redhat reference [bug 20357383]

[2.1.11-23]
- do not open files outside a dump directory
- Related: #1217484

[2.1.11-22]
- switch the default dump dir mode to 0750
- harden against directory traversal, crafted symbolic links
- avoid race-conditions in dump dir opening
- Resolves: #1212096, #1217499, #1218610, #1217484");

  script_tag(name:"affected", value:"'abrt, libreport' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"abrt", rpm:"abrt~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-ccpp", rpm:"abrt-addon-ccpp~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-kerneloops", rpm:"abrt-addon-kerneloops~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-pstoreoops", rpm:"abrt-addon-pstoreoops~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-python", rpm:"abrt-addon-python~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-upload-watch", rpm:"abrt-addon-upload-watch~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-vmcore", rpm:"abrt-addon-vmcore~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-xorg", rpm:"abrt-addon-xorg~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-cli", rpm:"abrt-cli~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-console-notification", rpm:"abrt-console-notification~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-dbus", rpm:"abrt-dbus~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-desktop", rpm:"abrt-desktop~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-devel", rpm:"abrt-devel~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-gui", rpm:"abrt-gui~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-gui-devel", rpm:"abrt-gui-devel~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-gui-libs", rpm:"abrt-gui-libs~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-libs", rpm:"abrt-libs~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-python", rpm:"abrt-python~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-python-doc", rpm:"abrt-python-doc~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-retrace-client", rpm:"abrt-retrace-client~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-tui", rpm:"abrt-tui~2.1.11~22.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport", rpm:"libreport~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-anaconda", rpm:"libreport-anaconda~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-cli", rpm:"libreport-cli~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-compat", rpm:"libreport-compat~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-devel", rpm:"libreport-devel~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-filesystem", rpm:"libreport-filesystem~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-gtk", rpm:"libreport-gtk~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-gtk-devel", rpm:"libreport-gtk-devel~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-newt", rpm:"libreport-newt~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-bugzilla", rpm:"libreport-plugin-bugzilla~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-kerneloops", rpm:"libreport-plugin-kerneloops~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-logger", rpm:"libreport-plugin-logger~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-mailx", rpm:"libreport-plugin-mailx~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-reportuploader", rpm:"libreport-plugin-reportuploader~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-ureport", rpm:"libreport-plugin-ureport~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-python", rpm:"libreport-python~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-rhel-anaconda-bugzilla", rpm:"libreport-rhel-anaconda-bugzilla~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-rhel-bugzilla", rpm:"libreport-rhel-bugzilla~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-web", rpm:"libreport-web~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-web-devel", rpm:"libreport-web-devel~2.1.11~23.0.1.el7_1", rls:"OracleLinux7"))) {
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
