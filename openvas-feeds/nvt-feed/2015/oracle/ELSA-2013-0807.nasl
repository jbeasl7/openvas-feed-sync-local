# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123630");
  script_cve_id("CVE-2012-5532");
  script_tag(name:"creation_date", value:"2015-10-06 11:06:29 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2013-0807)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2013-0807");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2013-0807.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hypervkvpd' package(s) announced via the ELSA-2013-0807 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0-0.7.0.1.el5_9.3]
- Add support for oracle os

[0-0.7.3]
- Fix for one more file descriptor leak (rhbz#953502)

[0-0.7.2]
- Validate Netlink source address (CVE-2012-5532) (rhbz#953560)

[0-0.7.1]
- Fix for file descriptor leak (rhbz#953502)");

  script_tag(name:"affected", value:"'hypervkvpd' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"hypervkvpd", rpm:"hypervkvpd~0~0.7.0.1.el5_9.3", rls:"OracleLinux5"))) {
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
