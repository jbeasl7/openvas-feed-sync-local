# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123409");
  script_cve_id("CVE-2014-0015", "CVE-2014-0138");
  script_tag(name:"creation_date", value:"2015-10-06 11:03:25 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_name("Oracle: Security Advisory (ELSA-2014-0561)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0561");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0561.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the ELSA-2014-0561 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[7.19.7-37.el6_5.3]
- fix re-use of wrong HTTP NTLM connection (CVE-2014-0015)
- fix connection re-use when using different log-in credentials (CVE-2014-0138)

[7.19.7-37.el6_5.2]
- fix authentication failure when server offers multiple auth options (#1096797)

[7.19.7-37.el6_5.1]
- refresh expired cookie in test172 from upstream test-suite (#1092486)
- fix a memory leak caused by write after close (#1092479)
- nss: implement non-blocking SSL handshake (#1092480)");

  script_tag(name:"affected", value:"'curl' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.19.7~37.el6_5.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl", rpm:"libcurl~7.19.7~37.el6_5.3", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.19.7~37.el6_5.3", rls:"OracleLinux6"))) {
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
