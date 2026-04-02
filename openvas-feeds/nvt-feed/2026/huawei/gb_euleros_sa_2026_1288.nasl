# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1288");
  script_cve_id("CVE-2026-0989", "CVE-2026-0990", "CVE-2026-0992");
  script_tag(name:"creation_date", value:"2026-03-10 04:52:39 +0000 (Tue, 10 Mar 2026)");
  script_version("2026-03-10T10:15:11+0000");
  script_tag(name:"last_modification", value:"2026-03-10 10:15:11 +0000 (Tue, 10 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-15 15:15:52 +0000 (Thu, 15 Jan 2026)");

  script_name("Huawei EulerOS: Security Advisory for libxml2 (EulerOS-SA-2026-1288)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1288");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1288");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libxml2' package(s) announced via the EulerOS-SA-2026-1288 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in the libxml2 library. This uncontrolled resource consumption vulnerability occurs when processing XML catalogs that contain repeated <nextCatalog> elements pointing to the same downstream catalog. A remote attacker can exploit this by supplying crafted catalogs, causing the parser to redundantly traverse catalog chains. This leads to excessive CPU consumption and degrades application availability, resulting in a denial-of-service condition.(CVE-2026-0992)

A flaw was found in libxml2, an XML parsing library. This uncontrolled recursion vulnerability occurs in the xmlCatalogXMLResolveURI function when an XML catalog contains a delegate URI entry that references itself. A remote attacker could exploit this configuration-dependent issue by providing a specially crafted XML catalog, leading to infinite recursion and call stack exhaustion. This ultimately results in a segmentation fault, causing a Denial of Service (DoS) by crashing affected applications.(CVE-2026-0990)

A flaw was identified in the RelaxNG parser of libxml2 related to how external schema inclusions are handled. The parser does not enforce a limit on inclusion depth when resolving nested <include> directives. Specially crafted or overly complex schemas can cause excessive recursion during parsing. This may lead to stack exhaustion and application crashes, creating a denial-of-service risk.(CVE-2026-0989)");

  script_tag(name:"affected", value:"'libxml2' package(s) on Huawei EulerOS V2.0SP13.");

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

  if(!isnull(res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.9.14~9.h17.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-libxml2", rpm:"python3-libxml2~2.9.14~9.h17.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
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
