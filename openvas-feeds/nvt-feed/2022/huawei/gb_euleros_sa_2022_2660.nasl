# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2022.2660");
  script_cve_id("CVE-2022-24805", "CVE-2022-24806", "CVE-2022-24807", "CVE-2022-24808", "CVE-2022-24809", "CVE-2022-24810");
  script_tag(name:"creation_date", value:"2022-11-03 04:26:17 +0000 (Thu, 03 Nov 2022)");
  script_version("2025-02-11T12:33:12+0000");
  script_tag(name:"last_modification", value:"2025-02-11 12:33:12 +0000 (Tue, 11 Feb 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-02-10 19:05:07 +0000 (Mon, 10 Feb 2025)");

  script_name("Huawei EulerOS: Security Advisory for net-snmp (EulerOS-SA-2022-2660)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2022-2660");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2022-2660");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'net-snmp' package(s) announced via the EulerOS-SA-2022-2660 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"SNMP (Simple Network Management Protocol) is a protocol used fornetwork management. The NET-SNMP project includes various SNMP toolsan extensible agent, an SNMP library, tools for requesting or settinginformation from SNMP agents, tools for generating and handling SNMPtraps, a version of the netstat(CVE-2022-24805)

SNMP (Simple Network Management Protocol) is a protocol used fornetwork management. The NET-SNMP project includes various SNMP toolsan extensible agent, an SNMP library, tools for requesting or settinginformation from SNMP agents, tools for generating and handling SNMPtraps, a version of the netstat(CVE-2022-24808)

SNMP (Simple Network Management Protocol) is a protocol used fornetwork management. The NET-SNMP project includes various SNMP toolsan extensible agent, an SNMP library, tools for requesting or settinginformation from SNMP agents, tools for generating and handling SNMPtraps, a version of the netstat(CVE-2022-24810)

SNMP (Simple Network Management Protocol) is a protocol used fornetwork management. The NET-SNMP project includes various SNMP toolsan extensible agent, an SNMP library, tools for requesting or settinginformation from SNMP agents, tools for generating and handling SNMPtraps, a version of the netstat(CVE-2022-24809)

SNMP (Simple Network Management Protocol) is a protocol used fornetwork management. The NET-SNMP project includes various SNMP toolsan extensible agent, an SNMP library, tools for requesting or settinginformation from SNMP agents, tools for generating and handling SNMPtraps, a version of the netstat(CVE-2022-24807)

SNMP (Simple Network Management Protocol) is a protocol used fornetwork management. The NET-SNMP project includes various SNMP toolsan extensible agent, an SNMP library, tools for requesting or settinginformation from SNMP agents, tools for generating and handling SNMPtraps, a version of the netstat(CVE-2022-24806)");

  script_tag(name:"affected", value:"'net-snmp' package(s) on Huawei EulerOS V2.0SP10.");

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

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"net-snmp", rpm:"net-snmp~5.9~3.h6.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"net-snmp-libs", rpm:"net-snmp-libs~5.9~3.h6.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-net-snmp", rpm:"python3-net-snmp~5.9~3.h6.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
