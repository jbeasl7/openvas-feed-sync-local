# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2761.1");
  script_cve_id("CVE-2020-24553");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:53 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-03 13:50:55 +0000 (Thu, 03 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2761-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2761-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202761-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.14' package(s) announced via the SUSE-SU-2020:2761-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for go1.14 fixes the following issues:

go1.14.9 (released 2020-09-09) includes fixes to the compiler, linker,
 runtime, documentation, and the net/http and testing packages. Refs
 bsc#1164903 go1.14 release tracking
 * go#41192 net/http/fcgi: race detected during execution of
 TestResponseWriterSniffsContentType test
 * go#41016 net/http: Transport.CancelRequest no longer cancels in-flight
 request
 * go#40973 net/http: RoundTrip unexpectedly changes Request
 * go#40968 runtime: checkptr incorrectly -race flagging when using &^
 arithmetic
 * go#40938 cmd/compile: R12 can be clobbered for write barrier call on
 PPC64
 * go#40848 testing: '=== PAUSE' lines do not change the test name for
 the next log line
 * go#40797 cmd/compile: inline marker targets not reachable after
 assembly on arm
 * go#40766 cmd/compile: inline marker targets not reachable after
 assembly on ppc64x
 * go#40501 cmd/compile: for range loop reading past slice end
 * go#40411 runtime: Windows service lifecycle events behave incorrectly
 when called within a golang environment
 * go#40398 runtime: fatal error: checkdead: runnable g
 * go#40192 runtime: pageAlloc.searchAddr may point to unmapped memory in
 discontiguous heaps, violating its invariant
 * go#39955 cmd/link: incorrect GC bitmap when global's type is in
 another shared object
 * go#39690 cmd/compile: s390x floating point <-> integer conversions
 clobbering the condition code
 * go#39279 net/http: Re-connect with upgraded HTTP2 connection fails to
 send Request.body
 * go#38904 doc: include fix for #34437 in Go 1.14 release notes

go1.14.8 (released 2020-09-01) includes security fixes to the
 net/http/cgi and net/http/fcgi packages. CVE-2020-24553 Refs bsc#1164903
 go1.14 release tracking
 * bsc#1176031 CVE-2020-24553
 * go#41164 net/http/cgi,net/http/fcgi: Cross-Site Scripting (XSS) when
 Content-Type is not specified");

  script_tag(name:"affected", value:"'go1.14' package(s) on SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP2.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"go1.14", rpm:"go1.14~1.14.9~1.18.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.14-doc", rpm:"go1.14-doc~1.14.9~1.18.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"go1.14", rpm:"go1.14~1.14.9~1.18.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.14-doc", rpm:"go1.14-doc~1.14.9~1.18.1", rls:"SLES15.0SP2"))) {
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
