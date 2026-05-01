# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2026.0094");
  script_cve_id("CVE-2025-59362", "CVE-2025-62168", "CVE-2026-32748", "CVE-2026-33515", "CVE-2026-33526");
  script_tag(name:"creation_date", value:"2026-04-13 05:06:37 +0000 (Mon, 13 Apr 2026)");
  script_version("2026-04-13T06:24:05+0000");
  script_tag(name:"last_modification", value:"2026-04-13 06:24:05 +0000 (Mon, 13 Apr 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-03-31 01:18:03 +0000 (Tue, 31 Mar 2026)");

  script_name("Mageia: Security Advisory (MGASA-2026-0094)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2026-0094");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2026-0094.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=35271");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-8157-1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/03/25/2");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/03/25/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2026/03/25/4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid' package(s) announced via the MGASA-2026-0094 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Squid mishandles ASN.1 encoding of long SNMP OIDs. This occurs in
asn_build_objid in lib/snmplib/asn1.c. (CVE-2025-59362)
Squid vulnerable to information disclosure via authentication credential
leakage in error handling. (CVE-2025-62168)
Squid vulnerable to Denial of Service in ICP Request handling.
(CVE-2026-33526)
Squid has Denial of Service in ICP Response handling. (CVE-2026-32748)
Squid has issues in ICP message handling. (CVE-2026-33515)");

  script_tag(name:"affected", value:"'squid' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"squid", rpm:"squid~5.9~1.5.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"squid-cachemgr", rpm:"squid-cachemgr~5.9~1.5.mga9", rls:"MAGEIA9"))) {
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
