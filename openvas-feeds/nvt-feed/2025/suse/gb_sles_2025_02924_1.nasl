# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.02924.1");
  script_cve_id("CVE-2025-4674", "CVE-2025-47906", "CVE-2025-47907");
  script_tag(name:"creation_date", value:"2025-08-22 04:11:56 +0000 (Fri, 22 Aug 2025)");
  script_version("2025-08-22T05:39:46+0000");
  script_tag(name:"last_modification", value:"2025-08-22 05:39:46 +0000 (Fri, 22 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:02924-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3|SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:02924-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-202502924-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1244485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1246118");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1247720");
  script_xref(name:"URL", value:"https://github.com/golang/go/wiki/Go-Release-Cycle");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-August/041307.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'go1.25' package(s) announced via the SUSE-SU-2025:02924-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"go1.25 (released 2025-08-12) is a major release of Go.

go1.25.x minor releases will be provided through August 2026.

 [link moved to references]

 go1.25 arrives six months after Go 1.24. Most of its changes are
 in the implementation of the toolchain, runtime, and
 libraries. As always, the release maintains the Go 1 promise of
 compatibility. We expect almost all Go programs to continue to
 compile and run as before.

 (boo#1244485 go1.25 release tracking)

 * Language changes: There are no languages changes that affect Go
 programs in Go 1.25. However, in the language specification the
 notion of core types has been removed in favor of dedicated
 prose. See the respective blog post for more information.
 * go command: The go build -asan option now defaults to doing
 leak detection at program exit. This will report an error if
 memory allocated by C is not freed and is not referenced by any
 other memory allocated by either C or Go. These new error
 reports may be disabled by setting ASAN_OPTIONS=detect_leaks=0
 in the environment when running the program.
 * go command: The Go distribution will include fewer prebuilt
 tool binaries. Core toolchain binaries such as the compiler and
 linker will still be included, but tools not invoked by build
 or test operations will be built and run by go tool as needed.
 * go command: The new go.mod ignore directive can be used to
 specify directories the go command should ignore. Files in
 these directories and their subdirectories will be ignored by
 the go command when matching package patterns, such as all or
 ./..., but will still be included in module zip files.
 * go command: The new go doc -http option will start a
 documentation server showing documentation for the requested
 object, and open the documentation in a browser window.
 * go command: The new go version -m -json option will print the
 JSON encodings of the runtime/debug.BuildInfo structures
 embedded in the given Go binary files.
 * go command: The go command now supports using a subdirectory of
 a repository as the path for a module root, when resolving a
 module path using the syntax <meta name='go-import'
 content='root-path vcs repo-url subdir'> to indicate that the
 root-path corresponds to the subdir of the repo-url with
 version control system vcs.
 * go command: The new work package pattern matches all packages
 in the work (formerly called main) modules: either the single
 work module in module mode or the set of workspace modules in
 workspace mode.
 * go command: When the go command updates the go line in a go.mod
 or go.work file, it no longer adds a toolchain line specifying
 the command's current version.
 * go vet: The go vet command includes new analyzers:
 * go vet: waitgroup reports misplaced calls to
 sync.WaitGroup.Add,
 * go vet: hostport reports uses of fmt.Sprintf('%s:%d', host,
 port) to construct addresses for net.Dial, as these will ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'go1.25' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"go1.25", rpm:"go1.25~1.25.0~150000.1.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-doc", rpm:"go1.25-doc~1.25.0~150000.1.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-race", rpm:"go1.25-race~1.25.0~150000.1.5.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"go1.25", rpm:"go1.25~1.25.0~150000.1.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-doc", rpm:"go1.25-doc~1.25.0~150000.1.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-race", rpm:"go1.25-race~1.25.0~150000.1.5.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"go1.25", rpm:"go1.25~1.25.0~150000.1.5.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-doc", rpm:"go1.25-doc~1.25.0~150000.1.5.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"go1.25-race", rpm:"go1.25-race~1.25.0~150000.1.5.1", rls:"SLES15.0SP5"))) {
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
