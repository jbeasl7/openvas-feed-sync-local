# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123960");
  script_cve_id("CVE-2011-4028");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:51 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"1.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2012-0303)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0303");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0303.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server' package(s) announced via the ELSA-2012-0303 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.1.1-48.90.0.1.el5]
- Added oracle-enterprise-detect.patch
- Replaced 'Red Hat' in spec file

[1.1.1-48.90]
- cve-2011-4028.patch: File existence disclosure vulnerability.

[1.1.1-48.88]
- cve-2011-4818.patch: Multiple input sanitization flaws in Render and GLX
- xorg-x11-server-1.1.0-mesa-copy-sub-buffer.patch: Likewise.

[1.1.1-48.87]
- xserver-1.1.1-fbdev-iterate-modes.patch: fix fbdev driver not iterating
 across all modes of a certain dimension (#740497)

[1.1.1-48.86]
- xserver-1.1.1-midc-double-free.patch: Don't double-free the picture for
 the root window when using the mi (software) cursor path. (#674741)

[1.1.1-48.85]
- xserver-1.1.1-bigreqs-buffer-size.patch: Fix BIG-REQUESTS buffer size
 (#555000)

[1.1.1-48.84]
- xserver-1.1.1-xinerama-crash.patch: Fix a crash in XineramaQueryScreens
 when client is swapped (#588346)

[1.1.1-48.83]
- xserver-1.1.1-xephyr-keymap.patch: Fix types in Xephyr keymap setup (#454409)

[1.1.1-48.82]
- xserver-1.1.1-wideline-overflow.patch: Fix integer overflow in wide line
 renderer (#649810)

[1.1.1-48.81]
- Fix mouse stuck on edge (#529717)

[1.1.1-48.80]
- xserver-1.1.1-bs-crash.patch: Fix a crash in backing store. (#676270)

[1.1.1-48.79]
- xserver-1.1.1-randr-fix-mouse-crossing.patch: fix zaphod mouse crossing (#559964)

[1.1.1-48.78]
- cve-2010-1166.patch: Fix broken modulo math in Render and arc code.
 Identical to xserver-1.1.1-mod-macro-parens.patch in 5.5.z. (#582651)

[1.1.1-48.77]
- xserver-1.1.1-dbe-validate-gc.patch: Validate the GC against both front
 and back buffers (#596899)");

  script_tag(name:"affected", value:"'xorg-x11-server' package(s) on Oracle Linux 5.");

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

if(release == "OracleLinux5") {

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~1.1.1~48.90.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xdmx", rpm:"xorg-x11-server-Xdmx~1.1.1~48.90.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xephyr", rpm:"xorg-x11-server-Xephyr~1.1.1~48.90.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xnest", rpm:"xorg-x11-server-Xnest~1.1.1~48.90.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xorg", rpm:"xorg-x11-server-Xorg~1.1.1~48.90.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xvfb", rpm:"xorg-x11-server-Xvfb~1.1.1~48.90.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xvnc-source", rpm:"xorg-x11-server-Xvnc-source~1.1.1~48.90.0.1.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-sdk", rpm:"xorg-x11-server-sdk~1.1.1~48.90.0.1.el5", rls:"OracleLinux5"))) {
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
