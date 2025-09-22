# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122041");
  script_cve_id("CVE-2011-1072");
  script_tag(name:"creation_date", value:"2015-10-06 11:12:06 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2011-1741)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux6");

  script_xref(name:"Advisory-ID", value:"ELSA-2011-1741");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2011-1741.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-pear' package(s) announced via the ELSA-2011-1741 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.9.4-4]
- fix patch application for #747361

[1.9.4-3]
- ignore REST cache creation failures as non-root user (#747361)

[1.9.4-2]
- fix XML-Util provides

[1.9.4-1]
- update to 1.9.4 (#651897)
- update XML_RPC to 1.5.4, Structures_Graph to 1.0.4, Archive_Tar to 1.3.7

[1.9.1-1]
- update to 1.9.1 (#651897)
- fix installation of XML_RPC license file");

  script_tag(name:"affected", value:"'php-pear' package(s) on Oracle Linux 6.");

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

  if(!isnull(res = isrpmvuln(pkg:"php-pear", rpm:"php-pear~1.9.4~4.el6", rls:"OracleLinux6"))) {
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
