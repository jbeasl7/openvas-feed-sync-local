# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123863");
  script_cve_id("CVE-2012-0441");
  script_tag(name:"creation_date", value:"2015-10-06 11:09:34 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-1090)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-1090");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-1090.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nspr, nss' package(s) announced via the ELSA-2012-1090 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"nspr
[4.9.1-4]
- Resolves: rhbz#834219 - Fix postinstall scriptlet failures
- Fix %post and %postun lines per packaging guidelines
- Updated License: to MPLv2.0 per upstream

[4.9.1-3]
- Resolves: rhbz#834219 - Ensure nspr-config.in changes get applied

[4.9.1-2]
- Resolves: rhbz#834219 - restore top section of nspr-config-pc.patch
- Needed to prevent multilib regressions

nss
[3.13.5-4.0.1.el5_8 ]
- Update clean.gif in the tarball

[3.13.5-4]
- Related: rhbz#834219 - Fix ia64 / i386 multilib nss install failure
- Remove no longer needed %pre and %preun scriplets meant for nss updates from RHEL-5.0

[3.13.5-3]
- Resolves: rhbz#834219 - Fix the changes to the %post line
- Having multiple commands requires that /sbin/lconfig be the beginning of the scriptlet

[3.13.5-2]
- Resolves: rhbz#834219 - Fix multilib and scriptlet problems
- Fix %post and %postun lines per packaging guildelines
- Add %{?_isa} to tools Requires: per packaging guidelines
- Fix explicit-lib-dependency zlib error reported by rpmlint

[3.13.5-1]
- Resolves: rhbz#834219 - Update RHEL 5.x to NSS 3.13.5 and NSPR 4.9.1 for Mozilla 10.0.6");

  script_tag(name:"affected", value:"'nspr, nss' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"nspr", rpm:"nspr~4.9.1~4.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nspr-devel", rpm:"nspr-devel~4.9.1~4.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.13.5~4.0.1.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-devel", rpm:"nss-devel~3.13.5~4.0.1.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-pkcs11-devel", rpm:"nss-pkcs11-devel~3.13.5~4.0.1.el5_8", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-tools", rpm:"nss-tools~3.13.5~4.0.1.el5_8", rls:"OracleLinux5"))) {
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
