# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1221");
  script_cve_id("CVE-2025-58185", "CVE-2025-58189", "CVE-2025-61723");
  script_tag(name:"creation_date", value:"2026-02-03 04:56:11 +0000 (Tue, 03 Feb 2026)");
  script_version("2026-02-03T05:55:35+0000");
  script_tag(name:"last_modification", value:"2026-02-03 05:55:35 +0000 (Tue, 03 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for golang (EulerOS-SA-2026-1221)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1221");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1221");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'golang' package(s) announced via the EulerOS-SA-2026-1221 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The processing time for parsing some invalid inputs scales non-linearly with respect to the size of the input. This affects programs which parse untrusted PEM inputs.(CVE-2025-61723)

Parsing a maliciously crafted DER payload could allocate large amounts of memory, causing memory exhaustion.(CVE-2025-58185)

When Conn.Handshake fails during ALPN negotiation the error contains attacker controlled information (the ALPN protocols sent by the client) which is not escaped.(CVE-2025-58189)");

  script_tag(name:"affected", value:"'golang' package(s) on Huawei EulerOS V2.0SP13.");

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

if(release == "EULEROS-2.0SP13") {

  if(!isnull(res = isrpmvuln(pkg:"golang", rpm:"golang~1.21.4~8.h116.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-devel", rpm:"golang-devel~1.21.4~8.h116.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"golang-help", rpm:"golang-help~1.21.4~8.h116.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
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
