# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2096.1");
  script_cve_id("CVE-2022-24823", "CVE-2022-41881", "CVE-2022-41915");
  script_tag(name:"creation_date", value:"2023-05-09 04:23:35 +0000 (Tue, 09 May 2023)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-19 16:55:03 +0000 (Mon, 19 Dec 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2096-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2096-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232096-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1199338");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206360");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1206379");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-May/014770.html");
  script_xref(name:"URL", value:"https://netty.io/news/2022/04/12/4-1-76-Final.html");
  script_xref(name:"URL", value:"https://netty.io/news/2022/05/06/2-1-77-Final.html");
  script_xref(name:"URL", value:"https://netty.io/news/2022/06/14/4-1-78-Final.html");
  script_xref(name:"URL", value:"https://netty.io/news/2022/07/11/4-1-79-Final.html");
  script_xref(name:"URL", value:"https://netty.io/news/2022/08/26/4-1-80-Final.html");
  script_xref(name:"URL", value:"https://netty.io/news/2022/09/08/4-1-81-Final.html");
  script_xref(name:"URL", value:"https://netty.io/news/2022/09/13/4-1-82-Final.html");
  script_xref(name:"URL", value:"https://netty.io/news/2022/10/11/4-1-84-Final.html");
  script_xref(name:"URL", value:"https://netty.io/news/2022/11/09/4-1-85-Final.html");
  script_xref(name:"URL", value:"https://netty.io/news/2022/12/12/4-1-86-Final.html");
  script_xref(name:"URL", value:"https://netty.io/news/2023/01/12/4-1-87-Final.html");
  script_xref(name:"URL", value:"https://netty.io/news/2023/02/12/4-1-88-Final.html");
  script_xref(name:"URL", value:"https://netty.io/news/2023/02/13/4-1-89-Final.html");
  script_xref(name:"URL", value:"https://netty.io/news/2023/03/14/4-1-90-Final.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netty, netty-tcnative' package(s) announced via the SUSE-SU-2023:2096-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for netty, netty-tcnative fixes the following issues:

netty:

- Security fixes included in this version update from 4.1.75 to 4.1.90:
 * CVE-2022-24823: Local Information Disclosure Vulnerability in Netty on Unix-Like systems due temporary files for
 Java 6 and lower in io.netty:netty-codec-http (bsc#1199338)
 * CVE-2022-41881: HAProxyMessageDecoder Stack Exhaustion DoS (bsc#1206360)
 * CVE-2022-41915: HTTP Response splitting from assigning header value iterator (bsc#1206379)

- Other non-security bug fixes included in this version update from 4.1.75 to 4.1.90:
 * Build with Java 11 on ix86 architecture in order to avoid build failures
 * Fix `HttpHeaders.names` for non-String headers
 * Fix `FlowControlHandler` behaviour to pass read events when auto-reading is turned off
 * Fix brotli compression
 * Fix a bug in FlowControlHandler that broke auto-read
 * Fix a potential memory leak bug has been in the pooled allocator
 * Fix a scalability issue caused by instanceof and check-cast checks that lead to false-sharing on the
 `Klass::secondary_super_cache` field in the JVM
 * Fix a bug in our `PEMParser` when PEM files have multiple objects, and `BouncyCastle` is on the classpath
 * Fix several `NullPointerException` bugs
 * Fix a regression `SslContext` private key loading
 * Fix a bug in `SslContext` private key reading fall-back path
 * Fix a buffer leak regression in `HttpClientCodec`
 * Fix a bug where some `HttpMessage` implementations, that also implement `HttpContent`, were not handled correctly
 * Fix epoll bug when receiving zero-sized datagrams
 * Fix a bug in `SslHandler` so `handlerRemoved` works properly even if `handlerAdded` throws an exception
 * Fix an issue that allowed the multicast methods on `EpollDatagramChannel` to be called outside of an event-loop
 thread
 * Fix a bug where an OPT record was added to DNS queries that already had such a record
 * Fix a bug that caused an error when files uploaded with HTTP POST contained a backslash in their name
 * Fix an issue in the `BlockHound` integration that could occasionally cause NetUtil to be reported as performing
 blocking operation. A similar `BlockHound` issue was fixed for the `JdkSslContext`
 * Fix a bug that prevented preface or settings frames from being flushed, when an HTTP2 connection was established
 with prior-knowledge
 * Fix a bug where Netty fails to load a shaded native library
 * Fix and relax overly strict HTTP/2 header validation check that was rejecting requests from Chrome and Firefox
 * Fix OpenSSL and BoringSSL implementations to respect the `jdk.tls.client.protocols` and `jdk.tls.server.protocols`
 system properties, making them react to these in the same way the JDK SSL provider does
 * Fix inconsitencies in how `epoll`, `kqueue`, and `NIO` handle RDHUP
 * For a more detailed list of changes please consult the official release notes:
 + Changes from 4.1.90: [link ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'netty, netty-tcnative' package(s) on SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"netty-tcnative", rpm:"netty-tcnative~2.0.59~150200.3.10.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"netty-tcnative", rpm:"netty-tcnative~2.0.59~150200.3.10.1", rls:"SLES15.0SP3"))) {
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
