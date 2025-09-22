# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1994");
  script_cve_id("CVE-2025-46420", "CVE-2025-46421", "CVE-2025-4948", "CVE-2025-4969");
  script_tag(name:"creation_date", value:"2025-08-12 04:32:34 +0000 (Tue, 12 Aug 2025)");
  script_version("2025-08-13T05:40:47+0000");
  script_tag(name:"last_modification", value:"2025-08-13 05:40:47 +0000 (Wed, 13 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-19 16:15:36 +0000 (Mon, 19 May 2025)");

  script_name("Huawei EulerOS: Security Advisory for libsoup (EulerOS-SA-2025-1994)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1994");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1994");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libsoup' package(s) announced via the EulerOS-SA-2025-1994 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found in the libsoup package. This flaw stems from its failure to correctly verify the termination of multipart HTTP messages. This can allow a remote attacker to send a specially crafted multipart HTTP body, causing the libsoup-consuming server to read beyond its allocated memory boundaries (out-of-bounds read).(CVE-2025-4969)

A flaw was found in the soup_multipart_new_from_message() function of the libsoup HTTP library, which is commonly used by GNOME and other applications to handle web communications. The issue occurs when the library processes specially crafted multipart messages. Due to improper validation, an internal calculation can go wrong, leading to an integer underflow. This can cause the program to access invalid memory and crash. As a result, any application or server using libsoup could be forced to exit unexpectedly, creating a denial-of-service (DoS) risk.(CVE-2025-4948)

A flaw was found in libsoup. When libsoup clients encounter an HTTP redirect, they mistakenly send the HTTP Authorization header to the new host that the redirection points to. This allows the new host to impersonate the user to the original host that issued the redirect.(CVE-2025-46421)

A flaw was found in libsoup. It is vulnerable to memory leaks in the soup_header_parse_quality_list() function when parsing a quality list that contains elements with all zeroes.(CVE-2025-46420)");

  script_tag(name:"affected", value:"'libsoup' package(s) on Huawei EulerOS V2.0SP13.");

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

  if(!isnull(res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.74.2~2.h10.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-help", rpm:"libsoup-help~2.74.2~2.h10.eulerosv2r13", rls:"EULEROS-2.0SP13"))) {
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
