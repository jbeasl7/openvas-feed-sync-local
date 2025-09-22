# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123966");
  script_cve_id("CVE-2011-0010");
  script_tag(name:"creation_date", value:"2015-10-06 11:10:56 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.4");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Oracle: Security Advisory (ELSA-2012-0309)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2012-0309");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2012-0309.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sudo' package(s) announced via the ELSA-2012-0309 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.7.2p1-13]
- patch: parse ldap.conf more closely to nss_ldap
 Resolves: rhbz#750318

[1.7.2p1-12]
- added patch for CVE-2011-0010
 Resolves: rhbz#757157

[1.7.2p1-11]
- backported selinux support from 1.7.4p5 (#477185, #673157)
- fixed bug in Runas_Spec group matching (#627543)
- disable 'sudo -l' output word wrapping if the output
 is piped (#697111)
- fixed overwriting of errno after execve failure (#673157)
- fixed segmentation fault (#673072)
- add a sudoers entry to the nsswitch.conf file
 on install (and delete it on uninstall) (#617061)
 Resolves: rhbz#697111
 Resolves: rhbz#673157
 Resolves: rhbz#673072
 Resolves: rhbz#627543
 Resolves: rhbz#617061
 Resolves: rhbz#477185");

  script_tag(name:"affected", value:"'sudo' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"sudo", rpm:"sudo~1.7.2p1~13.el5", rls:"OracleLinux5"))) {
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
