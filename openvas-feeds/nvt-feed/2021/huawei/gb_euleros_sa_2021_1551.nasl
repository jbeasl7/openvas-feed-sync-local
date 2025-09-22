# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1551");
  script_cve_id("CVE-2020-25681", "CVE-2020-25682", "CVE-2020-25683", "CVE-2020-25684", "CVE-2020-25685", "CVE-2020-25686", "CVE-2020-25687");
  script_tag(name:"creation_date", value:"2021-03-05 07:10:24 +0000 (Fri, 05 Mar 2021)");
  script_version("2024-05-17T05:05:27+0000");
  script_tag(name:"last_modification", value:"2024-05-17 05:05:27 +0000 (Fri, 17 May 2024)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-28 20:02:57 +0000 (Thu, 28 Jan 2021)");

  script_name("Huawei EulerOS: Security Advisory for dnsmasq (EulerOS-SA-2021-1551)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRTARM64\-3\.0\.6\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1551");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2021-1551");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'dnsmasq' package(s) announced via the EulerOS-SA-2021-1551 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in dnsmasq. A heap-based buffer overflow was discovered in dnsmasq when DNSSEC is enabled and before it validates the received DNS entries. This flaw allows a remote attacker, who can create valid DNS replies, to cause an overflow in a heap-allocated memory. This flaw is caused by the lack of length checks in rfc1035.c:extract_name(), which could be abused to make the code execute memcpy() with a negative size in sort_rrset() and cause a crash in dnsmasq, resulting in a denial of service. The highest threat from this vulnerability is to system availability.(CVE-2020-25687)

A flaw was found in dnsmasq. When receiving a query, dnsmasq does not check for an existing pending request for the same name and forwards a new request. By default, a maximum of 150 pending queries can be sent to upstream servers, so there can be at most 150 queries for the same name. This flaw allows an off-path attacker on the network to substantially reduce the number of attempts that it would have to perform to forge a reply and have it accepted by dnsmasq. This issue is mentioned in the 'Birthday Attacks' section of RFC5452. If chained with CVE-2020-25684, the attack complexity of a successful attack is reduced. The highest threat from this vulnerability is to data integrity.(CVE-2020-25686)

A flaw was found in dnsmasq. A heap-based buffer overflow was discovered in dnsmasq when DNSSEC is enabled and before it validates the received DNS entries. A remote attacker, who can create valid DNS replies, could use this flaw to cause an overflow in a heap-allocated memory. This flaw is caused by the lack of length checks in rfc1035.c:extract_name(), which could be abused to make the code execute memcpy() with a negative size in get_rdata() and cause a crash in dnsmasq, resulting in a denial of service. The highest threat from this vulnerability is to system availability.(CVE-2020-25685)

A flaw was found in dnsmasq. When getting a reply from a forwarded query, dnsmasq checks in the forward.c:reply_query() if the reply destination address/port is used by the pending forwarded queries. However, it does not use the address/port to retrieve the exact forwarded query, substantially reducing the number of attempts an attacker on the network would have to perform to forge a reply and get it accepted by dnsmasq. This issue contrasts with RFC5452, which specifies a query's attributes that all must be used to match a reply. This flaw allows an attacker to perform a DNS Cache Poisoning attack. If chained with CVE-2020-25685 or CVE-2020-25686, the attack complexity of a successful attack is reduced. The highest threat from this vulnerability is to data integrity.(CVE-2020-25684)

A flaw was found in dnsmasq. A heap-based buffer overflow was discovered in dnsmasq when DNSSEC is enabled and before it validates the received DNS entries. A remote attacker, who can create valid DNS replies, could use ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'dnsmasq' package(s) on Huawei EulerOS Virtualization for ARM 64 3.0.6.0.");

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

if(release == "EULEROSVIRTARM64-3.0.6.0") {

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq", rpm:"dnsmasq~2.79~7.h5.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dnsmasq-utils", rpm:"dnsmasq-utils~2.79~7.h5.eulerosv2r8", rls:"EULEROSVIRTARM64-3.0.6.0"))) {
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
