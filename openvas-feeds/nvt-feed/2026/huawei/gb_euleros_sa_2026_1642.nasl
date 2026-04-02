# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1642");
  script_cve_id("CVE-2025-11411");
  script_tag(name:"creation_date", value:"2026-03-19 04:58:29 +0000 (Thu, 19 Mar 2026)");
  script_version("2026-03-20T05:55:14+0000");
  script_tag(name:"last_modification", value:"2026-03-20 05:55:14 +0000 (Fri, 20 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for unbound (EulerOS-SA-2026-1642)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.13\.1");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1642");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1642");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'unbound' package(s) announced via the EulerOS-SA-2026-1642 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NLnet Labs Unbound up to and including version 1.24.0 is vulnerable to possible domain hijack attacks. Promiscuous NS RRSets that complement positive DNS replies in the authority section can be used to trick resolvers to update their delegation information for the zone. Usually these RRSets are used to update the resolver's knowledge of the zone's name servers. A malicious actor can exploit the possible poisonous effect by injecting NS RRSets (and possibly their respective address records) in a reply. This could be done for example by trying to spoof a packet or fragmentation attacks. Unbound would then proceed to update the NS RRSet data it already has since the new data has enough trust for it, i.e., in-zone data for the delegation point. Unbound 1.24.1 includes a fix that scrubs unsolicited NS RRSets (and their respective address records) from replies mitigating the possible poison effect.(CVE-2025-11411)");

  script_tag(name:"affected", value:"'unbound' package(s) on Huawei EulerOS Virtualization release 2.13.1.");

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

if(release == "EULEROSVIRT-2.13.1") {

  if(!isnull(res = isrpmvuln(pkg:"python3-unbound", rpm:"python3-unbound~1.13.2~8.h9.eulerosv2r13", rls:"EULEROSVIRT-2.13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-libs", rpm:"unbound-libs~1.13.2~8.h9.eulerosv2r13", rls:"EULEROSVIRT-2.13.1"))) {
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
