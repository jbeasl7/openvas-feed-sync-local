# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.6102419100999198");
  script_cve_id("CVE-2023-40030");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-31 14:35:56 +0000 (Thu, 31 Aug 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-6f419dc91b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-6f419dc91b");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-6f419dc91b");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2129110");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2130183");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2223438");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2234876");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236272");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-cargo, rust-cargo-c, rust-cargo-credential, rust-cargo-credential-libsecret, rust-cbindgen, rust-cbindgen0.24, rust-crates-io, rust-git2-curl' package(s) announced via the FEDORA-2023-6f419dc91b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update cargo-c to version 0.7.29+cargo-0.74.0.
- Update the cargo crate to version 0.74.0.
- Update cbindgen to version 0.26.0.
- Add a compat package version 0.24 of the bindgen crate.
- Update the crates-io crate to version 0.38.0.
- Update the git2-curl crate to version 0.18.0.
- Initial packaging of the cargo-credential and cargo-credential-libsecret crates.");

  script_tag(name:"affected", value:"'rust-cargo, rust-cargo-c, rust-cargo-credential, rust-cargo-credential-libsecret, rust-cbindgen, rust-cbindgen0.24, rust-crates-io, rust-git2-curl' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"cargo-c", rpm:"cargo-c~0.9.27~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cargo-c-debuginfo", rpm:"cargo-c-debuginfo~0.9.27~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cbindgen", rpm:"cbindgen~0.26.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cbindgen-debuginfo", rpm:"cbindgen-debuginfo~0.26.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo+default-devel", rpm:"rust-cargo+default-devel~0.74.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo+openssl-devel", rpm:"rust-cargo+openssl-devel~0.74.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo", rpm:"rust-cargo~0.74.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c+default-devel", rpm:"rust-cargo-c+default-devel~0.9.27~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c", rpm:"rust-cargo-c~0.9.27~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c-debugsource", rpm:"rust-cargo-c-debugsource~0.9.27~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-c-devel", rpm:"rust-cargo-c-devel~0.9.27~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-credential+default-devel", rpm:"rust-cargo-credential+default-devel~0.3.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-credential", rpm:"rust-cargo-credential~0.3.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-credential-devel", rpm:"rust-cargo-credential-devel~0.3.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-credential-libsecret+default-devel", rpm:"rust-cargo-credential-libsecret+default-devel~0.3.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-credential-libsecret", rpm:"rust-cargo-credential-libsecret~0.3.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-credential-libsecret-devel", rpm:"rust-cargo-credential-libsecret-devel~0.3.1~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cargo-devel", rpm:"rust-cargo-devel~0.74.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cbindgen+clap-devel", rpm:"rust-cbindgen+clap-devel~0.26.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cbindgen+default-devel", rpm:"rust-cbindgen+default-devel~0.26.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cbindgen", rpm:"rust-cbindgen~0.26.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cbindgen-debugsource", rpm:"rust-cbindgen-debugsource~0.26.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cbindgen-devel", rpm:"rust-cbindgen-devel~0.26.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cbindgen0.24+clap-devel", rpm:"rust-cbindgen0.24+clap-devel~0.24.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cbindgen0.24+default-devel", rpm:"rust-cbindgen0.24+default-devel~0.24.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cbindgen0.24", rpm:"rust-cbindgen0.24~0.24.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-cbindgen0.24-devel", rpm:"rust-cbindgen0.24-devel~0.24.5~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crates-io+default-devel", rpm:"rust-crates-io+default-devel~0.38.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crates-io", rpm:"rust-crates-io~0.38.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-crates-io-devel", rpm:"rust-crates-io-devel~0.38.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2-curl+default-devel", rpm:"rust-git2-curl+default-devel~0.18.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2-curl", rpm:"rust-git2-curl~0.18.0~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-git2-curl-devel", rpm:"rust-git2-curl-devel~0.18.0~1.fc40", rls:"FC40"))) {
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
