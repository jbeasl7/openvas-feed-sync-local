# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123735");
  script_cve_id("CVE-2010-4008", "CVE-2010-4494", "CVE-2011-0216", "CVE-2011-1944", "CVE-2011-2821", "CVE-2011-2834", "CVE-2011-3102", "CVE-2011-3905", "CVE-2011-3919", "CVE-2012-0841", "CVE-2012-5134");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:51 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0217)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0217");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0217.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw32-libxml2' package(s) announced via the ELSA-2013-0217 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.7.6-6]
- Synchronize patch-set with mainline-version.
- Bump version to 5, 6.
 Related: rhbz#891477

[2.7.6-4]
- Change release number to 4.
- Added patch libxml2-Fix-an-off-by-one-pointer-access.patch
- Added patch libxml2-Fix-a-segfault-on-XSD-validation-on-pattern-error.patch
- Added patch libxml2-Fix-entities-local-buffers-size-problems.patch
- Added patch libxml2-gnome-bug-561340-fix.patch
- Added patch for CVE-2012-0841
- Added patch for CVE-2011-0216
- Added patch for CVE-2011-2834
- Added patch for CVE-2011-3919
- Added patch for CVE-2011-1944
- Added patch for CVE-2011-3905
 Related: rhbz#891477");

  script_tag(name:"affected", value:"'mingw32-libxml2' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"mingw32-libxml2", rpm:"mingw32-libxml2~2.7.6~6.el6_3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mingw32-libxml2-static", rpm:"mingw32-libxml2-static~2.7.6~6.el6_3", rls:"OracleLinux6"))) {
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
