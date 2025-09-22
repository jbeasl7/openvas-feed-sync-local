# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.122639");
  script_cve_id("CVE-2007-3389", "CVE-2007-3390", "CVE-2007-3391", "CVE-2007-3392", "CVE-2007-3393");
  script_tag(name:"creation_date", value:"2015-10-08 11:49:58 +0000 (Thu, 08 Oct 2015)");
  script_version("2025-01-23T05:37:38+0000");
  script_tag(name:"last_modification", value:"2025-01-23 05:37:38 +0000 (Thu, 23 Jan 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Oracle: Security Advisory (ELSA-2007-0710)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Oracle Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/oracle_linux", "ssh/login/release", re:"ssh/login/release=OracleLinux5");

  script_xref(name:"Advisory-ID", value:"ELSA-2007-0710");
  script_xref(name:"URL", value:"https://linux.oracle.com/errata/ELSA-2007-0710.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the ELSA-2007-0710 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[0.99.6-1.el5.01]
- Added patch for OCFS2 formatting

[0.99.6-1]
- upgrade to 0.99.6
- Wireshark could crash when dissecting an HTTP chunked response
- Wireshark could crash while reading iSeries capture files
- Wireshark could exhaust system memory while reading a
 malformed DCP ETSI packet
- Wireshark could loop excessively while reading a malformed SSL packet
- Resolves: #247623");

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

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~0.99.6~1.el5.0.1", rls:"OracleLinux5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~0.99.6~1.el5.0.1", rls:"OracleLinux5"))) {
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
