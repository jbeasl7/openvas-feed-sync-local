# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0295.1");
  script_cve_id("CVE-2025-55130", "CVE-2025-55131", "CVE-2025-55132", "CVE-2025-59465", "CVE-2025-59466", "CVE-2026-21637", "CVE-2026-22036");
  script_tag(name:"creation_date", value:"2026-01-28 04:22:33 +0000 (Wed, 28 Jan 2026)");
  script_version("2026-01-28T05:49:43+0000");
  script_tag(name:"last_modification", value:"2026-01-28 05:49:43 +0000 (Wed, 28 Jan 2026)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-01-21 14:56:59 +0000 (Wed, 21 Jan 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0295-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0295-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260295-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256569");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256570");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256571");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256573");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256574");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256576");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1256848");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-January/023921.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs22' package(s) announced via the SUSE-SU-2026:0295-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2026-22036: Fixed unbounded decompression chain in HTTP response leading
 to resource exhaustion (bsc#1256848)
- CVE-2026-21637: Fixed synchronous exceptions thrown during callbacks that bypass
 TLS error handling and causing denial of service (bsc#1256576)
- CVE-2025-55132: Fixed futimes() ability to acces file even if process has read
 permissions only (bsc#1256571)
- CVE-2025-55131: Fixed race condition that allowed allocations with leftover data
 leading to in-process secrets exposure (bsc#1256570)
- CVE-2025-55130: Fixed filesystem permissions bypass via crafted symlinks (bsc#1256569)
- CVE-2025-59465: Fixed malformed HTTP/2 HEADERS frame with invalid HPACK leading
 to crash (bsc#1256573)
- CVE-2025-59466: Fixed uncatchable 'Maximum call stack size exceeded' error
 leading to crash (bsc#1256574)

Other fixes:

- Update to 22.22.0:
 * deps: updated undici to 6.23.0
 * deps: updated bundled c-ares to 1.34.6 (if used)
 * add TLSSocket default error handler
 * disable futimes when permission model is enabled
 * require full read and write to symlink APIs
 * rethrow stack overflow exceptions in async_hooks
 * refactor unsafe buffer creation to remove zero-fill toggle
 * route callback exceptions through error handlers

- Update to 22.21.1:
 * src: avoid unnecessary string -> char* -> string round trips
 * src: remove unnecessary shadowed functions on Utf8Value & BufferValue
 * process: fix hrtime fast call signatures
 * http: improve writeEarlyHints by avoiding for-of loop

- Update to 22.21.0:
 * cli: add --use-env-proxy
 * http: support http proxy for fetch under NODE_USE_ENV_PROXY
 * http: add shouldUpgradeCallback to let servers control HTTP upgrades
 * http,https: add built-in proxy support in http/https.request and Agent
 * src: add percentage support to --max-old-space-size

- Update to 22.20.0
 * doc: stabilize --disable-sigusr1
 * doc: mark path.matchesGlob as stable
 * http: add Agent.agentKeepAliveTimeoutBuffer option
 * http2: add support for raw header arrays in h2Stream.respond()
 * inspector: add http2 tracking support
 * sea: implement execArgvExtension
 * sea: support execArgv in sea config
 * stream: add brotli support to CompressionStream and DecompressionStream
 * test_runner: support object property mocking
 * worker: add cpu profile APIs for worker

- Update to 22.19.0
 * cli: add NODE_USE_SYSTEM_CA=1
 * cli: support ${pid} placeholder in --cpu-prof-name
 * crypto: add tls.setDefaultCACertificates()
 * dns: support max timeout
 * doc: update the instruction on how to verify releases
 * esm: unflag --experimental-wasm-modules
 * http: add server.keepAliveTimeoutBuffer option
 * lib: docs deprecate _http_*
 * net: update net.blocklist to allow file save and file management
 * process: add threadCpuUsage
 * zlib: add dictionary support to zstdCompress and zstdDecompress

- Update to 22.18.0:
 * deps: update amaro to 1.1.0
 * doc: add all ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'nodejs22' package(s) on SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs22", rpm:"nodejs22~22.22.0~150600.13.12.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-devel", rpm:"nodejs22-devel~22.22.0~150600.13.12.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs22-docs", rpm:"nodejs22-docs~22.22.0~150600.13.12.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm22", rpm:"npm22~22.22.0~150600.13.12.1", rls:"SLES15.0SP6"))) {
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
