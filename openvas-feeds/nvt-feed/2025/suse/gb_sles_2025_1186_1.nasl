# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2025.1186.1");
  script_cve_id("CVE-2024-8176");
  script_tag(name:"creation_date", value:"2025-04-11 04:08:10 +0000 (Fri, 11 Apr 2025)");
  script_version("2025-08-15T15:42:26+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:26 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-03-14 09:15:14 +0000 (Fri, 14 Mar 2025)");

  script_name("SUSE: Security Advisory (SUSE-SU-2025:1186-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2025:1186-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2025/suse-su-20251186-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1239618");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-updates/2025-April/038951.html");
  script_xref(name:"URL", value:"https://verbump.de/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'expat' package(s) announced via the SUSE-SU-2025:1186-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for expat fixes the following issues:

- CVE-2024-8176: Fixed denial of service from chaining a large number of entities caused
 by stack overflow by resolving use of recursion (bsc#1239618)

Other fixes:
- version update to 2.7.1 (jsc#PED-12500)
 Bug fixes:
 #980 #989 Restore event pointer behavior from Expat 2.6.4
 (that the fix to CVE-2024-8176 changed in 2.7.0),
 affected API functions are:
 - XML_GetCurrentByteCount
 - XML_GetCurrentByteIndex
 - XML_GetCurrentColumnNumber
 - XML_GetCurrentLineNumber
 - XML_GetInputContext
 Other changes:
 #976 #977 Autotools: Integrate files 'fuzz/xml_lpm_fuzzer.{cpp,proto}'
 with Automake that were missing from 2.7.0 release tarballs
 #983 #984 Fix printf format specifiers for 32bit Emscripten
 #992 docs: Promote OpenSSF Best Practices self-certification
 #978 tests/benchmark: Resolve mistaken double close
 #986 Address compiler warnings
 #990 #993 Version info bumped from 11:1:10 (libexpat*.so.1.10.1)
 to 11:2:10 (libexpat*.so.1.10.2), see [link moved to references]
 for what these numbers do
 Infrastructure:
 #982 CI: Start running Perl XML::Parser integration tests
 #987 CI: Enforce Clang Static Analyzer clean code
 #991 CI: Re-enable warning clang-analyzer-valist.Uninitialized
 for clang-tidy
 #981 CI: Cover compilation with musl
 #983 #984 CI: Cover compilation with 32bit Emscripten
 #976 #977 CI: Protect against fuzzer files missing from future
 release archives

- version update to 2.7.0
 #935 #937 Autotools: Make generated CMake files look for
 libexpat.@SO_MAJOR@.dylib on macOS
 #925 Autotools: Sync CMake templates with CMake 3.29
 #945 #962 #966 CMake: Drop support for CMake <3.13
 #942 CMake: Small fuzzing related improvements
 #921 docs: Add missing documentation of error code
 XML_ERROR_NOT_STARTED that was introduced with 2.6.4
 #941 docs: Document need for C++11 compiler for use from C++
 #959 tests/benchmark: Fix a (harmless) TOCTTOU
 #944 Windows: Fix installer target location of file xmlwf.xml
 for CMake
 #953 Windows: Address warning -Wunknown-warning-option
 about -Wno-pedantic-ms-format from LLVM MinGW
 #971 Address Cppcheck warnings
 #969 #970 Mass-migrate links from http:// to https://
 #947 #958 ..
 #974 #975 Document changes since the previous release
 #974 #975 Version info bumped from 11:0:10 (libexpat*.so.1.10.0)
 to 11:1:10 (libexpat*.so.1.10.1), see [link moved to references]
 for what these numbers do
 - Version info bumped from 9:3:8 to 9:4:8,
 see [link moved to references] for what these numbers do");

  script_tag(name:"affected", value:"'expat' package(s) on SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"expat", rpm:"expat~2.7.1~150000.3.36.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat-devel", rpm:"libexpat-devel~2.7.1~150000.3.36.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1", rpm:"libexpat1~2.7.1~150000.3.36.1", rls:"SLES15.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1-32bit", rpm:"libexpat1-32bit~2.7.1~150000.3.36.1", rls:"SLES15.0SP3"))) {
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
