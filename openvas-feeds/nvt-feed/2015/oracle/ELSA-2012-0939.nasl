# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123878");
  script_cve_id("CVE-2011-4028", "CVE-2011-4029");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:45 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2012-0939)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0939");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0939.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server' package(s) announced via the ELSA-2012-0939 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.10.6-1]
- xserver 1.10.6
- Use git-style patch names
- compsize.h, glxcmds.h: Copy from upstream git since they fell out of the
 upstream tarball

[1.10.4-15]
- Undo regression introduced in Patch8007 (#732467)

[1.10.4-14]
- xserver-1.10.4-sync-revert.patch: Revert an edge-case change in IDLETIME
 that appears to be more wrong than right. (#748704)

[1.10.4-13]
- xserver-1.10.4-randr-corner-case.patch: Fix a corner case in initial
 mode selection. (#657580)
- xserver-1.10.4-vbe-no-cache-ddc-support.patch: Only interpret complete
 non-support for DDC extension as 'DDC unavailable'. (#657580)

[1.10.4-11]
- xserver-1.10.4-dix-when-rescaling-from-master-rescale-from-desktop-.patch:
 fix rescaling from master to slave if the pointer (#732467)

[1.10.4-10]
- Add patches to change the screen crossing behaviour for multiple
 ScreenRecs (#732467)
- remove the xorg.conf.man page from our .gitignore - we need to patch it
 now and its part of the upstream distribution

[1.10.4-9]
- xserver-1.10.4-no-24bpp-xaa-composite.patch: Disable Composite at 24bpp
 in XAA (#651934)

[1.10.4-8]
- xserver-1.10.4-fb-picture-crash.patch: Fix crash on invalid pictures (#722680)

[1.10.4-7]
- fix xephyr rendering when using two screens (#757792)");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~1.10.6~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xdmx", rpm:"xorg-x11-server-Xdmx~1.10.6~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xephyr", rpm:"xorg-x11-server-Xephyr~1.10.6~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xnest", rpm:"xorg-x11-server-Xnest~1.10.6~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xorg", rpm:"xorg-x11-server-Xorg~1.10.6~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xvfb", rpm:"xorg-x11-server-Xvfb~1.10.6~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-common", rpm:"xorg-x11-server-common~1.10.6~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-devel", rpm:"xorg-x11-server-devel~1.10.6~1.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-source", rpm:"xorg-x11-server-source~1.10.6~1.el6", rls:"OracleLinux6"))) {
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
