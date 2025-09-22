# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123226");
  script_cve_id("CVE-2014-8091", "CVE-2014-8092", "CVE-2014-8093", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8097", "CVE-2014-8098", "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8101", "CVE-2014-8102");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:58 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-1982)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-1982");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-1982.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-x11-server' package(s) announced via the ELSA-2014-1982 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.1.1-48.107.0.1.el5_11]
- Added oracle-enterprise-detect.patch
- Replaced 'Red Hat' in spec file

[1.1.1-48.107]
- CVE-2014-8091 denial of service due to unchecked malloc in client
 authentication (#1168680)
- CVE-2014-8092 integer overflow in X11 core protocol requests when
 calculating memory needs for requests (#1168684)
- CVE-2014-8097 out of bounds access due to not validating length or offset
 values in DBE extension (#1168705)
- CVE-2014-8095 out of bounds access due to not validating length or offset
 values in XInput extension (#1168694)
- CVE-2014-8096 out of bounds access due to not validating length or offset
 values in XC-MISC extension(#1168700)
- CVE-2014-8099 out of bounds access due to not validating length or offset
 values in XVideo extension (#1168710)
- CVE-2014-8100 out of bounds access due to not validating length or offset
 values in Render extension (#1168711)
- CVE-2014-8102 out of bounds access due to not validating length or offset
 values in XFixes extension (#1168714)
- CVE-2014-8101 out of bounds access due to not validating length or offset
 values in RandR extension (#1168713)
- CVE-2014-8093 xorg-x11-server: integer overflow in GLX extension requests
 when calculating memory needs for requests (#1168688)
- CVE-2014-8098 xorg-x11-server: out of bounds access due to not validating
 length or offset values in GLX extension (#1168707)

[1.1.1-48.104]
- xserver-1.1.1-randr-config-timestamps.patch: Backport timestamp comparison
 fix from upstream RANDR code (#1006076)

[1.1.1-48.103]
- CVE-2013-6424: Fix OOB in trapezoid rasterization");

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

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server", rpm:"xorg-x11-server~1.1.1~48.107.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xdmx", rpm:"xorg-x11-server-Xdmx~1.1.1~48.107.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xephyr", rpm:"xorg-x11-server-Xephyr~1.1.1~48.107.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xnest", rpm:"xorg-x11-server-Xnest~1.1.1~48.107.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xorg", rpm:"xorg-x11-server-Xorg~1.1.1~48.107.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xvfb", rpm:"xorg-x11-server-Xvfb~1.1.1~48.107.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-Xvnc-source", rpm:"xorg-x11-server-Xvnc-source~1.1.1~48.107.0.1.el5_11", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xorg-x11-server-sdk", rpm:"xorg-x11-server-sdk~1.1.1~48.107.0.1.el5_11", rls:"OracleLinux5"))) {
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
