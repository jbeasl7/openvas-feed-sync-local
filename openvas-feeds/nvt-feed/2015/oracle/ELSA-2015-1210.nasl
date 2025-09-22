# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123084");
  script_cve_id("CVE-2015-1869", "CVE-2015-1870", "CVE-2015-3142", "CVE-2015-3147", "CVE-2015-3159", "CVE-2015-3315");
  script_tag(name:"creation_date", value:"2015-10-06 10:59:10 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-02-19 02:29:00 +0000 (Mon, 19 Feb 2018)");

  script_name("Oracle: Security Advisory (ELSA-2015-1210)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-1210");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-1210.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'abrt, libreport' package(s) announced via the ELSA-2015-1210 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"abrt
[2.0.8-26.0.1.el6_6.1]
- Add abrt-oracle-enterprise.patch to be product neutral
- Remove abrt-plugin-rhtsupport dependency for cli and desktop
- Make abrt Obsoletes/Provides abrt-plugin-rhtsupprot

[2.0.8-26.el6_6.1]
- remove old dump directories in upgrade
- remove outdated rmp scriptlets
- daemon: allow only root to submit CCpp, Koops, VMCore and Xorg problems
- abrt-action-install-debuginfo-to-abrt-cache: sanitize arguments and umask
- make the problem directories owned by abrt and the group root
- validate uploaded problem directories in abrt-handle-upload
- don't override nor remove files with user core dump files
- fix symbolic link and race condition flaws
- Resolves: #1211966

libreport
[2.0.9-21.0.1.el6_6.1]
- Add oracle-enterprise.patch and oracle-enterprise-po.patch
- Remove libreport-plugin-rhtsupport pkg

[2.0.9-21.el6_6.1]
- switch dump directory owner from 'abrt:user' to 'user:abrt' (rhbz#1212093)
- harden against directory traversal, crafted symbolic links (rhbz#1212093)
- avoid race-conditions in dump dir opening (rhbz#1212093)
- Resolves: #1211966");

  script_tag(name:"affected", value:"'abrt, libreport' package(s) on Oracle Linux 6.");

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

if(release == "OracleLinux6") {

  if(!isnull(res = isrpmvuln(pkg:"abrt", rpm:"abrt~2.0.8~26.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-ccpp", rpm:"abrt-addon-ccpp~2.0.8~26.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-kerneloops", rpm:"abrt-addon-kerneloops~2.0.8~26.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-python", rpm:"abrt-addon-python~2.0.8~26.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-addon-vmcore", rpm:"abrt-addon-vmcore~2.0.8~26.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-cli", rpm:"abrt-cli~2.0.8~26.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-console-notification", rpm:"abrt-console-notification~2.0.8~26.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-desktop", rpm:"abrt-desktop~2.0.8~26.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-devel", rpm:"abrt-devel~2.0.8~26.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-gui", rpm:"abrt-gui~2.0.8~26.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-libs", rpm:"abrt-libs~2.0.8~26.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-python", rpm:"abrt-python~2.0.8~26.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"abrt-tui", rpm:"abrt-tui~2.0.8~26.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport", rpm:"libreport~2.0.9~21.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-cli", rpm:"libreport-cli~2.0.9~21.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-compat", rpm:"libreport-compat~2.0.9~21.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-devel", rpm:"libreport-devel~2.0.9~21.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-filesystem", rpm:"libreport-filesystem~2.0.9~21.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-gtk", rpm:"libreport-gtk~2.0.9~21.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-gtk-devel", rpm:"libreport-gtk-devel~2.0.9~21.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-newt", rpm:"libreport-newt~2.0.9~21.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-bugzilla", rpm:"libreport-plugin-bugzilla~2.0.9~21.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-kerneloops", rpm:"libreport-plugin-kerneloops~2.0.9~21.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-logger", rpm:"libreport-plugin-logger~2.0.9~21.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-mailx", rpm:"libreport-plugin-mailx~2.0.9~21.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-plugin-reportuploader", rpm:"libreport-plugin-reportuploader~2.0.9~21.0.1.el6_6.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreport-python", rpm:"libreport-python~2.0.9~21.0.1.el6_6.1", rls:"OracleLinux6"))) {
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
