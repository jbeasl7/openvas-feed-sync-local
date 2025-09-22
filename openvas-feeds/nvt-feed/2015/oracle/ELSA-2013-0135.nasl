# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123755");
  script_cve_id("CVE-2012-2370");
  script_tag(name:"creation_date", value:"2015-10-06 11:08:06 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0135)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0135");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0135.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gtk2' package(s) announced via the ELSA-2013-0135 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.10.4-29]
- Improve patch to parse CUPS user lpoptions file to avoid crashes
 on s390 and ia64
 Resolves: #603809

[2.10.4-28]
- Fix the filechooser not opening selected file when location entry
 is empty
 Resolves: #518483

[2.10.4-27]
- Fix integer overflow in GdkPixbuf's XBM image file format loader
 (CVE-2012-2370)
 Resolves: #846252

[2.10.4-26]
- Fix crash when drag and dropping notebook tabs
 Resolves: #830901

[2.10.4-25]
- Fix a problem with Wacom tablets pen event positions when using dual
 head displays
 Resolves: #743658

[2.10.4-24]
- Backport a patch to parse CUPS user lpoptions file.
 Resolves: #603809");

  script_tag(name:"affected", value:"'gtk2' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gtk2", rpm:"gtk2~2.10.4~29.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gtk2-devel", rpm:"gtk2-devel~2.10.4~29.el5", rls:"OracleLinux5"))) {
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
