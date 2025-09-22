# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886795");
  script_cve_id("CVE-2024-24576");
  script_tag(name:"creation_date", value:"2024-05-27 10:47:54 +0000 (Mon, 27 May 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-ab4573fb3b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-ab4573fb3b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-ab4573fb3b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265585");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2274248");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust' package(s) announced via the FEDORA-2024-ab4573fb3b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security fix for CVE-2024-24576 (Windows command injection)");

  script_tag(name:"affected", value:"'rust' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"cargo", rpm:"cargo~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-debuginfo", rpm:"cargo-debuginfo~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clippy", rpm:"clippy~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clippy-debuginfo", rpm:"clippy-debuginfo~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust", rpm:"rust~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-analyzer", rpm:"rust-analyzer~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-analyzer-debuginfo", rpm:"rust-analyzer-debuginfo~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-debugger-common", rpm:"rust-debugger-common~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-debuginfo", rpm:"rust-debuginfo~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-debugsource", rpm:"rust-debugsource~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-doc", rpm:"rust-doc~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-gdb", rpm:"rust-gdb~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-lldb", rpm:"rust-lldb~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-src", rpm:"rust-src~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-std-static", rpm:"rust-std-static~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-std-static-aarch64-unknown-none-softfloat", rpm:"rust-std-static-aarch64-unknown-none-softfloat~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-std-static-i686-pc-windows-gnu", rpm:"rust-std-static-i686-pc-windows-gnu~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-std-static-wasm32-unknown-unknown", rpm:"rust-std-static-wasm32-unknown-unknown~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-std-static-wasm32-wasi", rpm:"rust-std-static-wasm32-wasi~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-std-static-x86_64-pc-windows-gnu", rpm:"rust-std-static-x86_64-pc-windows-gnu~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-std-static-x86_64-unknown-none", rpm:"rust-std-static-x86_64-unknown-none~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-std-static-x86_64-unknown-uefi", rpm:"rust-std-static-x86_64-unknown-uefi~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustfmt", rpm:"rustfmt~1.77.2~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rustfmt-debuginfo", rpm:"rustfmt-debuginfo~1.77.2~1.fc40", rls:"FC40"))) {
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
