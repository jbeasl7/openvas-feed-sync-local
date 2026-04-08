# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.20902.1");
  script_cve_id("CVE-2025-12105", "CVE-2025-14523", "CVE-2025-32049", "CVE-2026-1467", "CVE-2026-1539", "CVE-2026-1760", "CVE-2026-2369", "CVE-2026-2443", "CVE-2026-2708");
  script_tag(name:"creation_date", value:"2026-04-03 04:47:54 +0000 (Fri, 03 Apr 2026)");
  script_version("2026-04-07T07:51:48+0000");
  script_tag(name:"last_modification", value:"2026-04-07 07:51:48 +0000 (Tue, 07 Apr 2026)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-11 13:15:58 +0000 (Thu, 11 Dec 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:20902-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES16\.0\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:20902-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-202620902-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252555");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254876");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257398");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257597");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258120");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258170");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258508");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-April/025111.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsoup' package(s) announced via the SUSE-SU-2026:20902-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libsoup fixes the following issues:

Update to libsoup 3.6.6:

- CVE-2025-12105: heap use-after-free in message queue handling during HTTP/2 read completion (bsc#1252555).
- CVE-2025-14523: Duplicate Host Header Handling Causes Host-Parsing Discrepancy (bsc#1254876).
- CVE-2025-32049: Denial of Service attack to websocket server (bsc#1240751).
- CVE-2026-1467: lack of input sanitization can lead to unintended or unauthorized HTTP requests (bsc#1257398).
- CVE-2026-1539: proxy authentication credentials leaked via the Proxy-Authorization header when handling HTTP redirects
 (bsc#1257441).
- CVE-2026-1760: improper handling of HTTP requests combining certain headers by SoupServer can lead to HTTP request
 smuggling and potential DoS (bsc#1257597).
- CVE-2026-2369: Buffer overread due to integer underflow when handling zero-length resources (bsc#1258120).
- CVE-2026-2443: out-of-bounds read when processing specially crafted HTTP Range headers can lead to heap information
 disclosure to remote attackers (bsc#1258170).
- CVE-2026-2708: HTTP request smuggling via duplicate Content-Length headers (bsc#1258508).

Changelog:

- websocket: Fix out-of-bounds read in process_frame
- Check nulls returned by soup_date_time_new_from_http_string()
- Numerous fixes to handling of Range headers
- server: close the connection after responsing a request
containing Content-Length and Transfer-Encoding
- Use CRLF as line boundary when parsing chunked enconding data
- websocket: do not accept messages frames after closing due to
an error
- Sanitize filename of content disposition header values
- Always validate the headers value when coming from untrusted
source
- uri-utils: do host validation when checking if a GUri is valid
- multipart: check length of bytes read
soup_filter_input_stream_read_until()
- message-headers: Reject duplicate Host headers
- server: null-check soup_date_time_to_string()
- auth-digest: fix crash in
soup_auth_digest_get_protection_space()
- session: fix 'heap-use-after-free' caused by 'finishing' queue
item twice
- cookies: Avoid expires attribute if date is invalid
- http1: Set EOF flag once content-length bytes have been read
- date-utils: Add value checks for date/time parsing
- multipart: Fix multiple boundry limits
- Fixed multiple possible memory leaks
- message-headers: Correct merge of ranges
- body-input-stream: Correct chunked trailers end detection
- server-http2: Correctly validate URIs
- multipart: Fix read out of buffer bounds under
soup_multipart_new_from_message()
- headers: Ensure Request-Line comprises entire first line
- tests: Fix MSVC build error
- Fix possible deadlock on init from gmodule usage
- Updated translations.");

  script_tag(name:"affected", value:"'libsoup' package(s) on SUSE Linux Enterprise Server 16.0, SUSE Linux Enterprise Server for SAP Applications 16.0.");

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

if(release == "SLES16.0.0") {

  if(!isnull(res = isrpmvuln(pkg:"libsoup-3_0-0", rpm:"libsoup-3_0-0~3.6.6~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-devel", rpm:"libsoup-devel~3.6.6~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsoup-lang", rpm:"libsoup-lang~3.6.6~160000.1.1", rls:"SLES16.0.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Soup-3_0", rpm:"typelib-1_0-Soup-3_0~3.6.6~160000.1.1", rls:"SLES16.0.0"))) {
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
