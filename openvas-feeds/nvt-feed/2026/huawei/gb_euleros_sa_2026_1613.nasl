# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1613");
  script_cve_id("CVE-2025-11677", "CVE-2025-11678");
  script_tag(name:"creation_date", value:"2026-03-17 04:55:49 +0000 (Tue, 17 Mar 2026)");
  script_version("2026-03-17T05:57:28+0000");
  script_tag(name:"last_modification", value:"2026-03-17 05:57:28 +0000 (Tue, 17 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for libwebsockets (EulerOS-SA-2026-1613)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1613");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1613");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libwebsockets' package(s) announced via the EulerOS-SA-2026-1613 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Use After Free vulnerability exists in the WebSocket server implementation in lws_handshake_server in warmcat libwebsockets. In specific configurations where the user provides a callback function that handles LWS_CALLBACK_HTTP_CONFIRM_UPGRADE, an attacker may achieve denial of service.(CVE-2025-11677)

Stack-based Buffer Overflow in lws_adns_parse_label in warmcat libwebsockets allows, when the LWS_WITH_SYS_ASYNC_DNS flag is enabled during compilation, to overflow the label_stack, when the attacker is able to sniff a DNS request in order to craft a response with a matching id containing a label longer than the maximum.(CVE-2025-11678)");

  script_tag(name:"affected", value:"'libwebsockets' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"libwebsockets", rpm:"libwebsockets~4.3.0~2.h9.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
