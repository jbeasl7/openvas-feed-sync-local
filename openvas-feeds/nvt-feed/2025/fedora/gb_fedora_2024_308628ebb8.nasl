# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.30862810198988");
  script_cve_id("CVE-2015-2104", "CVE-2023-27043", "CVE-2024-0397", "CVE-2024-28757", "CVE-2024-4030", "CVE-2024-4032", "CVE-2024-45490", "CVE-2024-45491", "CVE-2024-45492", "CVE-2024-6232", "CVE-2024-6923", "CVE-2024-7592", "CVE-2024-8088");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-04 14:28:41 +0000 (Wed, 04 Sep 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-308628ebb8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-308628ebb8");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-308628ebb8");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2301899");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2310095");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/email.generator.html#module-email.generator");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/email.html#module-email");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/email.policy.html#email.policy.Policy.verify_generated_headers");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/email.utils.html#email.utils.getaddresses");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/email.utils.html#email.utils.parseaddr");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/http.cookies.html#module-http.cookies");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/os.html#os.mkdir");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/ssl.html#ssl.SSLContext");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/ssl.html#ssl.SSLContext.cert_store_stats");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/ssl.html#ssl.SSLContext.get_ca_certs");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/tempfile.html#tempfile.mkdtemp");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlunparse");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/urllib.parse.html#urllib.parse.urlunsplit");
  script_xref(name:"URL", value:"https://docs.python.org/3/library/zipfile.html#zipfile.Path");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-4hvh-m426-wv8w");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-5qxm-qvmj-8v79");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-784x-7qm2-gp97");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-ch5v-h69f-mxc8");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/102988");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/112275");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/113171");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/114572");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/116741");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/116773");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/118486");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/119690");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/121285");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/121650");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/121957");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/122133");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/122905");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/123067");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/123270");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/123678");
  script_xref(name:"URL", value:"https://github.com/python/cpython/issues/67693");
  script_xref(name:"URL", value:"https://www.python.org/downloads/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.9' package(s) announced via the FEDORA-2024-308628ebb8 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is a security release of Python 3.11
-----------------------------------------

**Note:** The release you're looking at is Python 3.11.10, a **security bugfix release** for the legacy 3.11 series. *Python 3.12* is now the latest feature release series of Python 3.

Security content in this release
--------------------------------

- [gh-123067]([link moved to references]): Fix quadratic complexity in parsing `'`-quoted cookie values with backslashes by [`http.cookies`]([link moved to references]). Fixes CVE-2024-7592.
- [gh-113171]([link moved to references]): Fixed various false positives and false negatives in IPv4Address.is_private, IPv4Address.is_global, IPv6Address.is_private, IPv6Address.is_global. Fixes CVE-2024-4032.
- [gh-67693]([link moved to references]): Fix [`urllib.parse.urlunparse()`]([link moved to references]) and [`urllib.parse.urlunsplit()`]([link moved to references]) for URIs with path starting with multiple slashes and no authority. Fixes CVE-2015-2104.
- [gh-121957]([link moved to references]): Fixed missing audit events around interactive use of Python, now also properly firing for `python -i`, as well as for `python -m asyncio`. The event in question is `cpython.run_stdin`.
- [gh-122133]([link moved to references]): Authenticate the socket connection for the `socket.socketpair()` fallback on platforms where `AF_UNIX` is not available like Windows.
- [gh-121285]([link moved to references]): Remove backtracking from tarfile header parsing for `hdrcharset`, PAX, and GNU sparse headers. That's CVE-2024-6232.
- [gh-114572]([link moved to references]): [`ssl.SSLContext.cert_store_stats()`]([link moved to references]) and [`ssl.SSLContext.get_ca_certs()`]([link moved to references]) now correctly lock access to the certificate store, when the [`ssl.SSLContext`]([link moved to references]) is shared across multiple threads.
- [gh-102988]([link moved to references]): [`email.utils.getaddresses()`]([link moved to references]) and [`email.utils.parseaddr()`]([link moved to references]) now return `('', '')` 2-tuples in more situations where invalid email addresses are encountered instead of potentially inaccurate values. Add optional *strict* parameter to these two functions: use `strict=False` to get the old behavior, accept malformed inputs. `getattr(email.utils, 'supports_strict_parsing', False)` can be use to check if the *strict* paramater is available. This improves the CVE-2023-27043 fix.
- [gh-123270]([link moved to references]): Sanitize names in [`zipfile.Path`]([link moved to references]) to avoid infinite loops ([gh-122905]([link moved to references])) without breaking contents using legitimate characters. That's CVE-2024-8088.
- [gh-121650]([link moved to references]): [`email`]([link moved to references]) headers with embedded newlines are now quoted on output. The [`generator`]([link moved to references]) will now refuse to serialize ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python3.9' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"python3.9", rpm:"python3.9~3.9.20~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.9-debuginfo", rpm:"python3.9-debuginfo~3.9.20~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.9-debugsource", rpm:"python3.9-debugsource~3.9.20~1.fc41", rls:"FC41"))) {
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
