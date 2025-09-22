# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122376");
  script_cve_id("CVE-2010-0734");
  script_tag(name:"creation_date", value:"2015-10-06 11:17:46 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2010-0273)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2010-0273");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2010-0273.html");
  script_xref(name:"URL", value:"http://curl.haxx.se/docs/adv_20100209.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the ELSA-2010-0273 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[7.15.5-9]
- [link moved to references] (#565408)

[7.15.5-8]
- mention lack of IPv6, FTPS and LDAP support while using a socks proxy
 (#473128)
- avoid tight loop if an upload connection is broken (#479967)
- add options --ftp-account and --ftp-alternative-to-user to program help
 (#517084)
- fix crash when reusing connection after negotiate-auth (#517199)
- support for CRL loading from a PEM file (#532069)

[7.15.5-7]
- sync patch for CVE-2007-0037 with 5.3.Z
Related: #485290

[7.15.5-6]
- fix CVE-2009-2417
Resolves: #516258

[7.15.5-5]
- forwardport one hunk from upstream curl-7.15.1
Related: #485290

[7.15.5-4]
- fix hunk applied to wrong place due to nonzero patch fuzz
Related: #485290

[7.15.5-3]
- fix CVE-2007-0037
Resolves: #485290");

  script_tag(name:"affected", value:"'curl' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.15.5~9.el5", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-devel", rpm:"curl-devel~7.15.5~9.el5", rls:"OracleLinux5"))) {
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
