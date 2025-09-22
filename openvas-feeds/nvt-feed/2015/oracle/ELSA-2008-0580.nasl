# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122541");
  script_cve_id("CVE-2007-2953", "CVE-2008-2712", "CVE-2008-3074", "CVE-2008-3075", "CVE-2008-4101", "CVE-2008-6235");
  script_tag(name:"creation_date", value:"2015-10-08 11:47:36 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2008-0580)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2008-0580");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2008-0580.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the ELSA-2008-0580 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[7.0.109-4.4z]
- fix netrw

[7.0.109-4.3z]
- fixes CVE-2008-3074 (tar plugin)
- fixes CVE-2008-3075 (zip plugin)
- fixes CVE-2008-3076 (netrw plugin)
- fixes CVE-2008-4101 (keyword and tag lookup)

[7.0.109-4.2z]
- fix some issues with netrw and remote file editing caused by
 the CVE-2008-2712 patch

[7.0.109-4.1z]
- more fixes for CVE-2008-2712

[7.0.109-4.z]
- fix release

[7.0.109-3.1z]
- rebuild for z stream

[7.0.109-3.6]
- re-enable debuginfo

[7.0.109-3.5]
- update netrw files for CVE-2008-2712

[7.0.109-3.4]
- add fixes for CVE-2007-2953 and CVE-2008-2712");

  script_tag(name:"affected", value:"'vim' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~7.0.109~4.el5_2.4z", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~7.0.109~4.el5_2.4z", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~7.0.109~4.el5_2.4z", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~7.0.109~4.el5_2.4z", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~7.0.109~4.el5_2.4z", rls:"OracleLinux5"))) {
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
