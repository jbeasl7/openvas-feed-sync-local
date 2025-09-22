# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2776.1");
  script_cve_id("CVE-2020-24553");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:53 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-03 13:50:55 +0000 (Thu, 03 Sep 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2776-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2776-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202776-1/");
  script_xref(name:"URL", value:"https://github.com/golang/go/wiki/Go-Release-Cycle");
  script_xref(name:"URL", value:"https://golang.org/doc/go1.15");
  script_xref(name:"URL", value:"https://proxy.golang.org");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.15' package(s) announced via the SUSE-SU-2020:2776-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"go1.15 (released 2020-08-11) Go 1.15 is a major release of Go.

go1.15.x minor releases will be provided through August 2021.

 [link moved to references]

Most changes are in the implementation of the toolchain, runtime, and libraries. As always, the release maintains the Go 1 promise of compatibility. We expect almost all Go programs to continue to compile
 and run as before.

See release notes [link moved to references]. Excerpts relevant to
 OBS environment and for SUSE/openSUSE follow:

Module support in the go command is ready for production use, and we
 encourage all users to migrate to Go modules for dependency management.

Module cache: The location of the module cache may now be set with the
 GOMODCACHE environment variable. The default value of GOMODCACHE is
 GOPATH[0]/pkg/mod, the location of the module cache before this change.

Compiler flag parsing: Various flag parsing issues in go test and go vet
 have been fixed. Notably, flags specified in GOFLAGS are handled more
 consistently, and the -outputdir flag now interprets relative paths
 relative to the working directory of the go command (rather than the
 working directory
 of each individual test).

The GOPROXY environment variable now supports skipping proxies that
 return errors. Proxy URLs may now be separated with either commas (,) or
 pipe characters (<pipe>). If a proxy URL is followed by a comma, the go
 command will only try the next proxy in the list after a 404 or 410 HTTP
 response. If a proxy URL is followed by a pipe character, the go command
 will try the next proxy in the list after any error. Note that the
 default value of GOPROXY remains [link moved to references],direct, which
 does not fall back to direct in case of errors.

On a Unix system, if the kill command or kill system call is used to
 send a SIGSEGV, SIGBUS, or SIGFPE signal to a Go program, and if the
 signal is not being handled via
 os/signal.Notify, the Go program will now reliably crash with a stack
 trace. In earlier releases the behavior was unpredictable.

Allocation of small objects now performs much better at high core
 counts, and has lower worst-case latency.

Go 1.15 reduces typical binary sizes by around 5% compared to Go 1.14 by
 eliminating certain types of GC metadata and more aggressively
 eliminating unused type metadata.

The toolchain now mitigates Intel CPU erratum SKX102 on GOARCH=amd64 by
 aligning functions to 32 byte boundaries and padding jump instructions.
 While this padding increases binary sizes, this is more than made up for
 by the binary size improvements mentioned above.

Go 1.15 adds a -spectre flag to both the compiler and the assembler, to
 allow enabling Spectre mitigations. These should almost never be needed
 and are provided mainly as a 'defense in depth' mechanism. See the
 Spectre Go wiki page for details.

The compiler now rejects //go: compiler directives ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'go1.15' package(s) on SUSE Linux Enterprise Module for Development Tools 15-SP1, SUSE Linux Enterprise Module for Development Tools 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"go1.15", rpm:"go1.15~1.15.2~1.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.15-doc", rpm:"go1.15-doc~1.15.2~1.3.1", rls:"SLES15.0SP1"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"go1.15", rpm:"go1.15~1.15.2~1.3.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.15-doc", rpm:"go1.15-doc~1.15.2~1.3.1", rls:"SLES15.0SP2"))) {
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
