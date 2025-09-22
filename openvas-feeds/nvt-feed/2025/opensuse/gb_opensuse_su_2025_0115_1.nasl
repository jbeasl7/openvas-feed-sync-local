# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.18.1.2025.0115.1");
  script_cve_id("CVE-2025-3066", "CVE-2025-3067", "CVE-2025-3068", "CVE-2025-3069", "CVE-2025-3070", "CVE-2025-3071", "CVE-2025-3072", "CVE-2025-3073", "CVE-2025-3074");
  script_tag(name:"creation_date", value:"2025-04-08 04:06:24 +0000 (Tue, 08 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("openSUSE Security Advisory (openSUSE-SU-2025:0115-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("openSUSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.6");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2025:0115-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/Q43DSNVGBXKUV4FSO2HJ4XARMZYOEIFU/");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1240555");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium, gn' package(s) announced via the openSUSE-SU-2025:0115-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium, gn fixes the following issues:

Changes in chromium:
- Chromium 135.0.7049.52 (stable release 2025-04-01) (boo#1240555)
 * CVE-2025-3066: Use after free in Navigations
 * CVE-2025-3067: Inappropriate implementation in Custom Tabs
 * CVE-2025-3068: Inappropriate implementation in Intents
 * CVE-2025-3069: Inappropriate implementation in Extensions
 * CVE-2025-3070: Insufficient validation of untrusted input in Extensions
 * CVE-2025-3071: Inappropriate implementation in Navigations
 * CVE-2025-3072: Inappropriate implementation in Custom Tabs
 * CVE-2025-3073: Inappropriate implementation in Autofill
 * CVE-2025-3074: Inappropriate implementation in Downloads

Changes in gn:
- Update to version 0.20250306:
 * Remove deps from rust executable to module's pcm files
 * Update test for rust executable deps
 * Add toolchain for cxx modules in TestWithScope
 * Apply the latest clang-format
 * Update reference for {rustdeps}
 * Always generate a .toolchain file even if it is empty.
 * Pass --with-lg-page=16 when building jemalloc for arm64.
 * Remove obsolete debug checks.
 * Make default vs ide version on Windows as 2022
 * Reland 'Adds a path_exists() function'
 * Revert 'Adds a path_exists() function'
 * Adds a path_exists() function
 * Revert 'Speed-up GN with custom OutputStream interface.'
 * Speed-up GN with custom OutputStream interface.
 * Add `exec_script_allowlist` to replace `exec_script_whitelist`.
 * Retry ReplaceFile in case of failure
 * Fix crash when NinjaBuildWriter::RunAndWriteFile fails
 * fix include for escape.h
 * fix exit code for gn gen failure
 * misc: Use html.escape instead of cgi.escape
 * Do not copy parent build_dependency_files_ in Scope constructors.
 * Improve error message for duplicated items
 * [rust-project] Always use forward slashes in sysroot paths
 * Update all_dependent_configs docs.
 * set 'no_stamp_files' by default
 * fix a typo
 * Stop using transitional LFS64 APIs
 * do not use tool prefix for phony rule
 * [rust] Add sysroot_src to rust-project.json
 * Implement and enable 'no_stamp_files'
 * Add Target::dependency_output_alias()
 * Add 'outputs' to generated_file documentation.
 * Update bug database link.
 * remove a trailing space after variable bindings
 * fix tool name in error
 * remove unused includes
 * Markdown optimization (follow-up)
 * Support link_output, depend_output in Rust linked tools.
 * Properly verify runtime_outputs in rust tool definitions.
 * BugFix: Syntax error in gen.py file
 * generated_file: add output to input deps of stamp
 * Markdown optimization:
 * Revert 'Rust: link_output, depend_output and runtime_outputs for dylibs'
 * hint using nogncheck on disallowed includes");

  script_tag(name:"affected", value:"'chromium, gn' package(s) on openSUSE Leap 15.6.");

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

if(release == "openSUSELeap15.6") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~135.0.7049.52~bp156.2.102.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~135.0.7049.52~bp156.2.102.2", rls:"openSUSELeap15.6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gn", rpm:"gn~0.20250306~bp156.2.6.1", rls:"openSUSELeap15.6"))) {
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
