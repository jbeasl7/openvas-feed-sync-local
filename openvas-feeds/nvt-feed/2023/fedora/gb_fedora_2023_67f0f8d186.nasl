# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885201");
  script_cve_id("CVE-2023-29941");
  script_tag(name:"creation_date", value:"2023-11-05 02:20:34 +0000 (Sun, 05 Nov 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-11 18:23:11 +0000 (Thu, 11 May 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-67f0f8d186)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-67f0f8d186");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-67f0f8d186");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2225597");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2241873");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2242208");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clang, compiler-rt, flang, libclc, libcxx, libomp, lld, lldb, llvm, llvm-bolt, llvm-test-suite, mlir, polly, python-lit' package(s) announced via the FEDORA-2023-67f0f8d186 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to LLVM 17.0.2");

  script_tag(name:"affected", value:"'clang, compiler-rt, flang, libclc, libcxx, libomp, lld, lldb, llvm, llvm-bolt, llvm-test-suite, mlir, polly, python-lit' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"clang", rpm:"clang~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang-analyzer", rpm:"clang-analyzer~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang-debuginfo", rpm:"clang-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang-debugsource", rpm:"clang-debugsource~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang-devel", rpm:"clang-devel~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang-devel-debuginfo", rpm:"clang-devel-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang-libs", rpm:"clang-libs~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang-libs-debuginfo", rpm:"clang-libs-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang-resource-filesystem", rpm:"clang-resource-filesystem~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang-tools-extra", rpm:"clang-tools-extra~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang-tools-extra-debuginfo", rpm:"clang-tools-extra-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clang-tools-extra-devel", rpm:"clang-tools-extra-devel~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"compiler-rt", rpm:"compiler-rt~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"compiler-rt-debuginfo", rpm:"compiler-rt-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"compiler-rt-debugsource", rpm:"compiler-rt-debugsource~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flang", rpm:"flang~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flang-debuginfo", rpm:"flang-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flang-debugsource", rpm:"flang-debugsource~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flang-devel", rpm:"flang-devel~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"flang-doc", rpm:"flang-doc~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"git-clang-format", rpm:"git-clang-format~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclc", rpm:"libclc~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libclc-devel", rpm:"libclc-devel~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcxx", rpm:"libcxx~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcxx-debuginfo", rpm:"libcxx-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcxx-debugsource", rpm:"libcxx-debugsource~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcxx-devel", rpm:"libcxx-devel~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcxx-static", rpm:"libcxx-static~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcxxabi", rpm:"libcxxabi~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcxxabi-debuginfo", rpm:"libcxxabi-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcxxabi-devel", rpm:"libcxxabi-devel~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcxxabi-static", rpm:"libcxxabi-static~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libomp", rpm:"libomp~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libomp-debuginfo", rpm:"libomp-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libomp-debugsource", rpm:"libomp-debugsource~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libomp-devel", rpm:"libomp-devel~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lld", rpm:"lld~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lld-debuginfo", rpm:"lld-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lld-debugsource", rpm:"lld-debugsource~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lld-devel", rpm:"lld-devel~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lld-libs", rpm:"lld-libs~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lld-libs-debuginfo", rpm:"lld-libs-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lldb", rpm:"lldb~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lldb-debuginfo", rpm:"lldb-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lldb-debugsource", rpm:"lldb-debugsource~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lldb-devel", rpm:"lldb-devel~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm", rpm:"llvm~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-bolt", rpm:"llvm-bolt~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-bolt-debuginfo", rpm:"llvm-bolt-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-bolt-debugsource", rpm:"llvm-bolt-debugsource~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-bolt-doc", rpm:"llvm-bolt-doc~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-cmake-utils", rpm:"llvm-cmake-utils~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-debuginfo", rpm:"llvm-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-debugsource", rpm:"llvm-debugsource~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-devel", rpm:"llvm-devel~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-devel-debuginfo", rpm:"llvm-devel-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-doc", rpm:"llvm-doc~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-googletest", rpm:"llvm-googletest~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-libs", rpm:"llvm-libs~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-libs-debuginfo", rpm:"llvm-libs-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-libunwind", rpm:"llvm-libunwind~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-libunwind-debuginfo", rpm:"llvm-libunwind-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-libunwind-devel", rpm:"llvm-libunwind-devel~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-libunwind-doc", rpm:"llvm-libunwind-doc~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-libunwind-static", rpm:"llvm-libunwind-static~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-static", rpm:"llvm-static~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-test", rpm:"llvm-test~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-test-debuginfo", rpm:"llvm-test-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"llvm-test-suite", rpm:"llvm-test-suite~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlir", rpm:"mlir~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlir-debuginfo", rpm:"mlir-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlir-debugsource", rpm:"mlir-debugsource~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlir-devel", rpm:"mlir-devel~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlir-devel-debuginfo", rpm:"mlir-devel-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlir-static", rpm:"mlir-static~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polly", rpm:"polly~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polly-debuginfo", rpm:"polly-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polly-debugsource", rpm:"polly-debugsource~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polly-devel", rpm:"polly-devel~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"polly-doc", rpm:"polly-doc~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-lit", rpm:"python-lit~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-clang", rpm:"python3-clang~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lit", rpm:"python3-lit~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-lldb", rpm:"python3-lldb~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mlir", rpm:"python3-mlir~17.0.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-mlir-debuginfo", rpm:"python3-mlir-debuginfo~17.0.2~1.fc39", rls:"FC39"))) {
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
