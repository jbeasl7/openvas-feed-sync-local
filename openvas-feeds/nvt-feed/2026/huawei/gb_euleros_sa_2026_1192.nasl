# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2026.1192");
  script_cve_id("CVE-2024-11168", "CVE-2025-1795", "CVE-2025-4516", "CVE-2025-6069", "CVE-2025-8194");
  script_tag(name:"creation_date", value:"2026-02-02 04:58:24 +0000 (Mon, 02 Feb 2026)");
  script_version("2026-02-02T05:59:28+0000");
  script_tag(name:"last_modification", value:"2026-02-02 05:59:28 +0000 (Mon, 02 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for python3 (EulerOS-SA-2026-1192)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROSVIRT\-2\.10\.0");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2026-1192");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2026-1192");
  script_xref(name:"URL", value:"https://gist.github.com/sethmlarson/1716ac5b82b73dbcbf23ad2eff8b33e1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'python3' package(s) announced via the EulerOS-SA-2026-1192 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"There is a defect in the CPython 'tarfile' module affecting the 'TarFile' extraction and entry enumeration APIs. The tar implementation would process tar archives with negative offsets without error, resulting in an infinite loop and deadlock during the parsing of maliciously crafted tar archives. This vulnerability can be mitigated by including the following patch after importing the 'tarfile' module: [link moved to references](CVE-2025-8194)

During an address list folding when a separating comma ends up on a folded line and that line is to be unicode-encoded then the separator itself is also unicode-encoded. Expected behavior is that the separating comma remains a plan comma. This can result in the address header being misinterpreted by some mail servers.(CVE-2025-1795)

The html.parser.HTMLParser class had worse-case quadratic complexity when processing certain crafted malformed inputs potentially leading to amplified denial-of-service.(CVE-2025-6069)

There is an issue in CPython when using `bytes.decode('unicode_escape', error='ignore<pipe>replace')`. If you are not using the 'unicode_escape' encoding or an error handler your usage is not affected. To work-around this issue you may stop using the error= handler and instead wrap the bytes.decode() call in a try-except catching the DecodeError.(CVE-2025-4516)

The urllib.parse.urlsplit() and urlparse() functions improperly validated bracketed hosts (`[]`), allowing hosts that weren't IPv6 or IPvFuture. This behavior was not conformant to RFC 3986 and potentially enabled SSRF if a URL is processed by more than one URL parser.(CVE-2024-11168)");

  script_tag(name:"affected", value:"'python3' package(s) on Huawei EulerOS Virtualization release 2.10.0.");

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

if(release == "EULEROSVIRT-2.10.0") {

  if(!isnull(res = isrpmvuln(pkg:"python3", rpm:"python3~3.7.9~9.h39.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-fgo", rpm:"python3-fgo~3.7.9~9.h39.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-unversioned-command", rpm:"python3-unversioned-command~3.7.9~9.h39.eulerosv2r10", rls:"EULEROSVIRT-2.10.0"))) {
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
