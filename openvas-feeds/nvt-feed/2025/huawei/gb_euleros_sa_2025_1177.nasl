# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1177");
  script_cve_id("CVE-2024-52530", "CVE-2024-52531", "CVE-2024-52532");
  script_tag(name:"creation_date", value:"2025-02-10 09:04:52 +0000 (Mon, 10 Feb 2025)");
  script_version("2025-02-11T05:38:07+0000");
  script_tag(name:"last_modification", value:"2025-02-11 05:38:07 +0000 (Tue, 11 Feb 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for libsoup (EulerOS-SA-2025-1177)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1177");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1177");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libsoup' package(s) announced via the EulerOS-SA-2025-1177 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNOME libsoup before 3.6.0 allows HTTP request smuggling in some configurations because '\0' characters at the end of header names are ignored, i.e., a 'Transfer-Encoding\0: chunked' header is treated the same as a 'Transfer-Encoding: chunked' header.(CVE-2024-52530)

GNOME libsoup before 3.6.1 allows a buffer overflow in applications that perform conversion to UTF-8 in soup_header_parse_param_list_strict. Input received over the network cannot trigger this.(CVE-2024-52531)

GNOME libsoup before 3.6.1 has an infinite loop, and memory consumption. during the reading of certain patterns of WebSocket data from clients.(CVE-2024-52532)");

  script_tag(name:"affected", value:"'libsoup' package(s) on Huawei EulerOS V2.0SP12.");

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

if(release == "EULEROS-2.0SP12") {

  if(!isnull(res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.74.2~2.h3.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-help", rpm:"libsoup-help~2.74.2~2.h3.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
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
