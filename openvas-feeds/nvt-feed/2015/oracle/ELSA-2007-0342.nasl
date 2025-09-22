# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122682");
  script_cve_id("CVE-2007-1841");
  script_tag(name:"creation_date", value:"2015-10-08 11:51:03 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_name("Oracle: Security Advisory (ELSA-2007-0342)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2007-0342");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2007-0342.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ipsec-tools' package(s) announced via the ELSA-2007-0342 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.6.5-8]
 - Upstream fix for Racoon DOS, informational delete must be encrypted
 - Resolves: rhbz#235388 - CVE-2007-1841 ipsec-tools racoon DoS

 [0.6.5-7]
 - Resolves: #218386 labeled ipsec does not work over loopback

 [0.6.5-6.6]
 - Related: #232508 add auditing to racoon

 [0.6.5-6.5]
 - Resolves: #235680 racoon socket descriptor exhaustion

 [0.6.5-6.4]
 - Resolves: #236121 increase buffer for context

 [0.6.5-6.3]
 - Resolves: #234491 kernel sends ACQUIRES that racoon is not catching
 - Resolves: #218386 labeled ipsec does not work over loopback


 [0.6.5-6.2.el5]
 - fix for setting the security context into a proposal (32<->64bit)
 - Resolves: rhbz#232508");

  script_tag(name:"affected", value:"'ipsec-tools' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"ipsec-tools", rpm:"ipsec-tools~0.6.5~8.el5", rls:"OracleLinux5"))) {
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
