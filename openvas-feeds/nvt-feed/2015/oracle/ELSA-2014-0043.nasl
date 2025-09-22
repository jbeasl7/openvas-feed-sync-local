# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123481");
  script_cve_id("CVE-2014-0591");
  script_tag(name:"creation_date", value:"2015-10-06 11:04:27 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2014-0043)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0043");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0043.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the ELSA-2014-0043 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[32:9.8.2-0.23.rc1.1]
- Fix CVE-2014-0591

[32:9.8.2-0.23.rc1]
- Fix gssapictx memory leak (#911167)

[32:9.8.2-0.22.rc1]
- fix CVE-2013-4854

[32:9.8.2-0.21.rc1]
- fix CVE-2013-2266
- ship dns/rrl.h in -devel subpkg

[32:9.8.2-0.20.rc1]
- remove one bogus file from /usr/share/doc, introduced by RRL patch

[32:9.8.2-0.19.rc1]
- fix CVE-2012-5689

[32:9.8.2-0.18.rc1]
- add response rate limit patch (#873624)");

  script_tag(name:"affected", value:"'bind' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.8.2~0.23.rc1.el6_5.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chroot", rpm:"bind-chroot~9.8.2~0.23.rc1.el6_5.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.8.2~0.23.rc1.el6_5.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.8.2~0.23.rc1.el6_5.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-sdb", rpm:"bind-sdb~9.8.2~0.23.rc1.el6_5.1", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.8.2~0.23.rc1.el6_5.1", rls:"OracleLinux6"))) {
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
