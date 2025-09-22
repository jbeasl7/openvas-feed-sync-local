# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0573.1");
  script_cve_id("CVE-2023-32731", "CVE-2023-32732", "CVE-2023-33953", "CVE-2023-44487", "CVE-2023-4785");
  script_tag(name:"creation_date", value:"2024-02-22 04:21:09 +0000 (Thu, 22 Feb 2024)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-19 16:02:53 +0000 (Tue, 19 Sep 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0573-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0573-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240573-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1133277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1182659");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1203378");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1208794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1212182");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1214148");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1215334");
  script_xref(name:"URL", value:"https://developers.google.com/protocol-buffers/docs/news/2022-05-06#python-updates");
  script_xref(name:"URL", value:"https://github.com/abseil/abseil-cpp/releases/tag/20230125.3");
  script_xref(name:"URL", value:"https://github.com/protocolbuffers/protobuf");
  script_xref(name:"URL", value:"https://github.com/protocolbuffers/protobuf/issues/8129");
  script_xref(name:"URL", value:"https://github.com/protocolbuffers/protobuf/releases/tag/v22.0");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2024-February/017985.html");
  script_xref(name:"URL", value:"https://protobuf.dev/support/migration/#compiler-22");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'abseil-cpp, grpc, opencensus-proto, protobuf, python-abseil, python-grpcio, re2' package(s) announced via the SUSE-SU-2024:0573-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for abseil-cpp, grpc, opencensus-proto, protobuf, python-abseil, python-grpcio, re2 fixes the following issues:

abseil-cpp was updated to:

Update to 20230802.1:

* Add StdcppWaiter to the end of the list of waiter implementations

Update to 20230802.0

 What's New:

 * Added the nullability library for designating the expected
 nullability of pointers. Currently these serve as annotations
 only, but it is expected that compilers will one day be able
 to use these annotations for diagnostic purposes.
 * Added the prefetch library as a portable layer for moving data
 into caches before it is read.
 * Abseil's hash tables now detect many more programming errors
 in debug and sanitizer builds.
 * Abseil's synchronization objects now differentiate absolute
 waits (when passed an absl::Time) from relative waits (when
 passed an absl::Duration) when the underlying platform supports
 differentiating these cases. This only makes a difference when
 system clocks are adjusted.
 * Abseil's flag parsing library includes additional methods that
 make it easier to use when another library also expects to be
 able to parse flags.
 * absl::string_view is now available as a smaller target,
 @com_google_absl//absl/strings:string_view, so that users may
 use this library without depending on the much larger
 @com_google_absl//absl/strings target.

Update to 20230125.3

Details can be found on:

 [link moved to references]

Update to 20230125.2

What's New:

 The Abseil logging library has been released. This library
 provides facilities for writing short text messages about the
 status of a program to stderr, disk files, or other sinks
 (via an extension API). See the logging library documentation
 for more information.
 An extension point, AbslStringify(), allows user-defined types
 to seamlessly work with Abseil's string formatting functions
 like absl::StrCat() and absl::StrFormat().
 A library for computing CRC32C checksums has been added.
 Floating-point parsing now uses the Eisel-Lemire algorithm,
 which provides a significant speed improvement.
 The flags library now provides suggestions for the closest
 flag(s) in the case of misspelled flags.
 Using CMake to install Abseil now makes the installed artifacts
 (in particular absl/base/options.h) reflect the compiled ABI.

 Breaking Changes:

 Abseil now requires at least C++14 and follows Google's Foundational
 C++ Support Policy. See this table for a list of currently supported
 versions compilers, platforms, and build tools.
 The legacy spellings of the thread annotation macros/functions
 (e.g. GUARDED_BY()) have been removed by default in favor of the
 ABSL_ prefixed versions (e.g. ABSL_GUARDED_BY()) due to clashes with
 other libraries. The compatibility macro ABSL_LEGACY_THREAD_ANNOTATIONS
 can be defined on the compile command-line to temporarily restore these
 spellings, but this compatibility macro will be ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'abseil-cpp, grpc, opencensus-proto, protobuf, python-abseil, python-grpcio, re2' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"abseil-cpp-devel", rpm:"abseil-cpp-devel~20230802.1~150400.10.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0", rpm:"libabsl2308_0_0~20230802.1~150400.10.4.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrpc++1_60", rpm:"libgrpc++1_60~1.60.0~150400.8.3.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrpc1_60", rpm:"libgrpc1_60~1.60.0~150400.8.3.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgrpc37", rpm:"libgrpc37~1.60.0~150400.8.3.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0", rpm:"libprotobuf-lite25_1_0~25.1~150400.9.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf25_1_0", rpm:"libprotobuf25_1_0~25.1~150400.9.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotoc25_1_0", rpm:"libprotoc25_1_0~25.1~150400.9.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libre2-11", rpm:"libre2-11~20240201~150400.9.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libupb37", rpm:"libupb37~1.60.0~150400.8.3.2", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"protobuf-devel", rpm:"protobuf-devel~25.1~150400.9.3.1", rls:"SLES15.0SP4"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"libabsl2308_0_0", rpm:"libabsl2308_0_0~20230802.1~150400.10.4.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libprotobuf-lite25_1_0", rpm:"libprotobuf-lite25_1_0~25.1~150400.9.3.1", rls:"SLES15.0SP5"))) {
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
