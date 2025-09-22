# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.1829");
  script_cve_id("CVE-2025-2784", "CVE-2025-32050", "CVE-2025-32052", "CVE-2025-32053", "CVE-2025-32906", "CVE-2025-32907", "CVE-2025-32909", "CVE-2025-32910", "CVE-2025-32911", "CVE-2025-32912", "CVE-2025-32913", "CVE-2025-32914", "CVE-2025-46420", "CVE-2025-46421", "CVE-2025-4948", "CVE-2025-4969");
  script_tag(name:"creation_date", value:"2025-07-21 04:42:46 +0000 (Mon, 21 Jul 2025)");
  script_version("2025-07-21T05:44:15+0000");
  script_tag(name:"last_modification", value:"2025-07-21 05:44:15 +0000 (Mon, 21 Jul 2025)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-15 16:16:06 +0000 (Tue, 15 Apr 2025)");

  script_name("Huawei EulerOS: Security Advisory for libsoup (EulerOS-SA-2025-1829)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-1829");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-1829");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'libsoup' package(s) announced via the EulerOS-SA-2025-1829 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A flaw was found in libsoup. A vulnerability in sniff_feed_or_html() and skip_insignificant_space() functions may lead to a heap buffer over-read.(CVE-2025-32053)

A flaw was found in libsoup. A vulnerability in the sniff_unknown() function may lead to heap buffer over-read.(CVE-2025-32052)

A flaw was found in libsoup, where soup_auth_digest_authenticate() is vulnerable to a NULL pointer dereference. This issue may cause the libsoup client to crash.(CVE-2025-32910)

A use-after-free type vulnerability was found in libsoup, in the soup_message_headers_get_content_disposition() function. This flaw allows a malicious HTTP client to cause memory corruption in the libsoup server.(CVE-2025-32911)

A flaw was found in libsoup, where SoupAuthDigest is vulnerable to a NULL pointer dereference. The HTTP server may cause the libsoup client to crash.(CVE-2025-32912)

A flaw was found in libsoup. The implementation of HTTP range requests is vulnerable to a resource consumption attack. This flaw allows a malicious client to request the same range many times in a single HTTP request, causing the server to use large amounts of memory. This does not allow for a full denial of service.(CVE-2025-32907)

A flaw was found in libsoup, where the soup_headers_parse_request() function may be vulnerable to an out-of-bound read. This flaw allows a malicious user to use a specially crafted HTTP request to crash the HTTP server.(CVE-2025-32906)

A flaw was found in libsoup. SoupContentSniffer may be vulnerable to a NULL pointer dereference in the sniff_mp4 function. The HTTP server may cause the libsoup client to crash.(CVE-2025-32909)

A flaw was found in libsoup, where the soup_message_headers_get_content_disposition() function is vulnerable to a NULL pointer dereference. This flaw allows a malicious HTTP peer to crash a libsoup client or server that uses this function.(CVE-2025-32913)

A flaw was found in libsoup, where the soup_multipart_new_from_message() function is vulnerable to an out-of-bounds read. This flaw allows a malicious HTTP client to induce the libsoup server to read out of bounds.(CVE-2025-32914)

A flaw was found in libsoup. The libsoup append_param_quoted() function may contain an overflow bug resulting in a buffer under-read.(CVE-2025-32050)

A flaw was found in libsoup. The package is vulnerable to a heap buffer over-read when sniffing content via the skip_insight_whitespace() function. Libsoup clients may read one byte out-of-bounds in response to a crafted HTTP response by an HTTP server.(CVE-2025-2784)

A flaw was found in libsoup. It is vulnerable to memory leaks in the soup_header_parse_quality_list() function when parsing a quality list that contains elements with all zeroes.(CVE-2025-46420)

A flaw was found in libsoup. When libsoup clients encounter an HTTP redirect, they mistakenly send the HTTP Authorization header to the new host that the redirection points to. ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"libsoup", rpm:"libsoup~2.74.2~2.h8.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-help", rpm:"libsoup-help~2.74.2~2.h8.eulerosv2r12", rls:"EULEROS-2.0SP12"))) {
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
