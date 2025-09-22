# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123177");
  script_cve_id("CVE-2014-8105");
  script_tag(name:"creation_date", value:"2015-10-06 11:00:20 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Oracle: Security Advisory (ELSA-2015-0628)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-0628");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-0628.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base' package(s) announced via the ELSA-2015-0628 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.2.11.15-50]
- Release 1.2.11.15-50
- Resolves: #1179099 - Problem with single value attribute MMR replication (DS 47915, DS 569)

[1.2.11.15-49]
- Release 1.2.11.15-49
- Resolves: #1180629 - CVE-2014-8105: information disclosure through 'cn=changelog' subtree
- Resolves: #1179099 - Problem with single value attribute MMR replication (DS 47915)
- Resolves: #1179595 - default nsslapd-sasl-max-buffer-size should be 2MB (DS 47457)
- Resolves: #1179100 - ACI's are replaced by 'ACI_ALL' after editing group of ACI's including invalid one (DS 47953)");

  script_tag(name:"affected", value:"'389-ds-base' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.2.11.15~50.el6_6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-devel", rpm:"389-ds-base-devel~1.2.11.15~50.el6_6", rls:"OracleLinux6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.2.11.15~50.el6_6", rls:"OracleLinux6"))) {
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
