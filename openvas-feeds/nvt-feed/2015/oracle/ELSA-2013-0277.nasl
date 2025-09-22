# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123712");
  script_cve_id("CVE-2012-3411");
  script_tag(name:"creation_date", value:"2015-10-06 11:07:33 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2013-0277)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0277");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0277.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dnsmasq' package(s) announced via the ELSA-2013-0277 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[2.48-13]
- Fix the DHCP RELEASE problem when two or more dnsmasq instances are running (rhbz#887156)

[2.48-12]
- Fixing initscript restart stop functions (rhbz#850944)

[2.48-11]
- Revert previous changes because of many problems with --bind-dynamic option backport.
- Dropping dnsmasq-2.48-add-bind-dynamic-option.patch
- Set SO_BINDTODEVICE socket option when using --bind-interfaces (rhbz#884957)

[2.48-10]
- Fixed dnsmasq-2.48-add-bind-dynamic-option.patch
 - the option --bind-dynamic was not set correctly when used

[2.48-9]
- Added cc flag -fno-strict-aliasing to solve Testsuite regressions

[2.48-8]
- Fix CVE-2012-3411 (rhbz#882251)

[2.48-7]
- Fix lease-change script (rhbz#815819)
- Check tftp-root exists and is accessible at startup (rhbz#824214)");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq", rpm:"dnsmasq~2.48~13.el6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq-utils", rpm:"dnsmasq-utils~2.48~13.el6", rls:"OracleLinux6"))) {
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
