# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1249");
  script_cve_id("CVE-2025-14523", "CVE-2026-0719");
  script_tag(name:"creation_date", value:"2026-03-10 04:52:39 +0000 (Tue, 10 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-13 06:15:49 +0000 (Tue, 13 Jan 2026)");

  script_name("Huawei EulerOS: Security Advisory for libsoup (EulerOS-SA-2026-1249)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1249");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1249");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libsoup' package(s) announced via the EulerOS-SA-2026-1249 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw in libsoup's HTTP header handling allows multiple Host: headers in a request and returns the last occurrence for server-side processing. Common front proxies often honor the first Host: header, so this mismatch can cause vhost confusion where a proxy routes a request to one backend but the backend interprets it as destined for another host. This discrepancy enables request-smuggling style attacks, cache poisoning, or bypassing host-based access controls when an attacker supplies duplicate Host headers.(CVE-2025-14523)

A flaw was identified in the NTLM authentication handling of the libsoup HTTP library, used by GNOME and other applications for network communication. When processing extremely long passwords, an internal size calculation can overflow due to improper use of signed integers. This results in incorrect memory allocation on the stack, followed by unsafe memory copying. As a result, applications using libsoup may crash unexpectedly, creating a denial-of-service risk.(CVE-2026-0719)");

  script_tag(name:"affected", value:"'libsoup' package(s) on Huawei EulerOS V2.0SP13(x86_64).");

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

if(release == "EULEROS-2.0SP13-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.74.2~2.h14.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-help", rpm:"libsoup-help~2.74.2~2.h14.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
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
