# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.123435");
  script_cve_id("CVE-2012-5595", "CVE-2012-5598", "CVE-2012-5599", "CVE-2012-5600", "CVE-2012-6056", "CVE-2012-6060", "CVE-2012-6061", "CVE-2012-6062", "CVE-2013-3557", "CVE-2013-3559", "CVE-2013-4081", "CVE-2013-4083", "CVE-2013-4927", "CVE-2013-4931", "CVE-2013-4932", "CVE-2013-4933", "CVE-2013-4934", "CVE-2013-4935", "CVE-2013-5721", "CVE-2013-7112", "CVE-2014-2281", "CVE-2014-2299");
  script_tag(name:"creation_date", value:"2015-10-06 11:03:46 +0000 (Tue, 06 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Oracle: Security Advisory (ELSA-2014-0341)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2014-0341");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2014-0341.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the ELSA-2014-0341 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[1.0.15-6.0.1.el5]
- Added oracle-ocfs2-network.patch
- increase max packet size to 65536 (Herbert van den Bergh) [orabug 13542633]

[1.0.15-6]
- security patches
- Resolves: CVE-2012-6056
 CVE-2012-6060
 CVE-2012-6061
 CVE-2012-6062
 CVE-2013-3557
 CVE-2013-3559
 CVE-2013-4081
 CVE-2013-4083
 CVE-2013-4927
 CVE-2013-4931
 CVE-2013-4932
 CVE-2013-4933
 CVE-2013-4934
 CVE-2013-4935
 CVE-2013-5721
 CVE-2013-7112
 CVE-2014-2281
 CVE-2014-2299");

  script_tag(name:"affected", value:"'wireshark' package(s) on Oracle Linux 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.0.15~6.0.1.el5_10", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.0.15~6.0.1.el5_10", rls:"OracleLinux5"))) {
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
