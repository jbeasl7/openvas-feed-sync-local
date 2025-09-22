# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122746");
  script_cve_id("CVE-2014-8119");
  script_tag(name:"creation_date", value:"2015-11-24 08:17:21 +0000 (Tue, 24 Nov 2015)");
  script_version("2025-01-23T05:37:39+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:39 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-22 17:48:00 +0000 (Mon, 22 Apr 2019)");

  script_name("Oracle: Security Advisory (ELSA-2015-2248)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux7");

  script_xref(name:"Advisory-ID", value:"ELSA-2015-2248");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2015-2248.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netcf' package(s) announced via the ELSA-2015-2248 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.2.8-1]
- Rebase to netcf-0.2.8
 - resolve rhbz#1165965 - CVE-2014-8119
 - resolve rhbz#1159000
 - support multiple IPv4 addresses in interface config (redhat driver)
 - resolve rhbz#1113983
 - allow static IPv4 config simultaneous with DHCPv4 (redhat driver)
 - resolve rhbz#1170941
 - remove extra quotes from IPV6ADDR_SECONDARIES (redhat+suse drivers)
 - resolve rhbz#1090011
 - limit names of new interfaces to IFNAMSIZ characters
 - resolve rhbz#761246
 - properly parse ifcfg files with comments past column 1");

  script_tag(name:"affected", value:"'netcf' package(s) on Oracle Linux 7.");

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

if(release == "OracleLinux7") {

  if(!isnull(res = isrpmvuln(pkg:"netcf", rpm:"netcf~0.2.8~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcf-devel", rpm:"netcf-devel~0.2.8~1.el7", rls:"OracleLinux7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netcf-libs", rpm:"netcf-libs~0.2.8~1.el7", rls:"OracleLinux7"))) {
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
