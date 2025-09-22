# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123969");
  script_cve_id("CVE-2011-1675", "CVE-2011-1677");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:59 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-0307)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0307");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0307.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'util-linux' package(s) announced via the ELSA-2012-0307 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.13-0.59.0.1.el5]
- Merge UEK modification
 fix #10104470 - Import hwclock from util-linux-ng [Kris Van Hees]

[2.13-0.59]
- fix #768382 - CVE-2011-1675 CVE-2011-1677 util-linux various flaws

[2.13-0.58]
- fix #677452 - util-linux fails to build with gettext-0.17

[2.13-0.57]
- fix #646300 - login doesn't update /var/run/utmp properly
- fix #726572 - import missing fsfreeze into util-linux
- fix #678430 - fdisk should not report error on 1gB LUNs
- fix #699639 - mount man page is missing support for ext4/xfs
- fix #650937 - blockdev man page missing information
- fix #678407 - ipcs and ipcrm in wrong man section");

  script_tag(name:"affected", value:"'util-linux' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"util-linux", rpm:"util-linux~2.13~0.59.0.1.el5", rls:"OracleLinux5"))) {
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
