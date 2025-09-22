# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1015");
  script_cve_id("CVE-2024-33655", "CVE-2024-8508");
  script_tag(name:"creation_date", value:"2025-01-14 04:31:02 +0000 (Tue, 14 Jan 2025)");
  script_version("2025-08-15T05:40:49+0000");
  script_tag(name:"last_modification", value:"2025-08-15 05:40:49 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-12-17 19:28:03 +0000 (Tue, 17 Dec 2024)");

  script_name("Huawei EulerOS: Security Advisory for unbound (EulerOS-SA-2025-1015)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1015");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1015");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'unbound' package(s) announced via the EulerOS-SA-2025-1015 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The DNS protocol in RFC 1035 and updates allows remote attackers to cause a denial of service (resource consumption) by arranging for DNS queries to be accumulated for seconds, such that responses are later sent in a pulsing burst (which can be considered traffic amplification in some cases), aka the 'DNSBomb' issue.(CVE-2024-33655)

NLnet Labs Unbound up to and including version 1.21.0 contains a vulnerability when handling replies with very large RRsets that it needs to perform name compression for. Malicious upstreams responses with very large RRsets can cause Unbound to spend a considerable time applying name compression to downstream replies. This can lead to degraded performance and eventually denial of service in well orchestrated attacks. The vulnerability can be exploited by a malicious actor querying Unbound for the specially crafted contents of a malicious zone with very large RRsets. Before Unbound replies to the query it will try to apply name compression which was an unbounded operation that could lock the CPU until the whole packet was complete. Unbound version 1.21.1 introduces a hard limit on the number of name compression calculations it is willing to do per packet. Packets that need more compression will result in semi-compressed packets or truncated packets, even on TCP for huge messages, to avoid locking the CPU for long. This change should not affect normal DNS traffic.(CVE-2024-8508)");

  script_tag(name:"affected", value:"'unbound' package(s) on Huawei EulerOS V2.0SP10.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3-unbound", rpm:"python3-unbound~1.11.0~2.h12.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound", rpm:"unbound~1.11.0~2.h12.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"unbound-libs", rpm:"unbound-libs~1.11.0~2.h12.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
