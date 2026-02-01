# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.801214971009897");
  script_tag(name:"creation_date", value:"2026-01-23 04:22:04 +0000 (Fri, 23 Jan 2026)");
  script_version("2026-01-23T05:49:25+0000");
  script_tag(name:"last_modification", value:"2026-01-23 05:49:25 +0000 (Fri, 23 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-801214adba)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-801214adba");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-801214adba");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2026-0001");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-rkyv0.7, rust-rkyv_derive0.7' package(s) announced via the FEDORA-2026-801214adba advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"[link moved to references]");

  script_tag(name:"affected", value:"'rust-rkyv0.7, rust-rkyv_derive0.7' package(s) on Fedora 42.");

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

if(release == "FC42") {

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+alloc-devel", rpm:"rust-rkyv0.7+alloc-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+arbitrary_enum_discriminant-devel", rpm:"rust-rkyv0.7+arbitrary_enum_discriminant-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+archive_be-devel", rpm:"rust-rkyv0.7+archive_be-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+archive_le-devel", rpm:"rust-rkyv0.7+archive_le-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+arrayvec-devel", rpm:"rust-rkyv0.7+arrayvec-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+bytecheck-devel", rpm:"rust-rkyv0.7+bytecheck-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+copy-devel", rpm:"rust-rkyv0.7+copy-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+copy_unsafe-devel", rpm:"rust-rkyv0.7+copy_unsafe-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+default-devel", rpm:"rust-rkyv0.7+default-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+hashbrown-devel", rpm:"rust-rkyv0.7+hashbrown-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+rend-devel", rpm:"rust-rkyv0.7+rend-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+size_16-devel", rpm:"rust-rkyv0.7+size_16-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+size_32-devel", rpm:"rust-rkyv0.7+size_32-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+size_64-devel", rpm:"rust-rkyv0.7+size_64-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+std-devel", rpm:"rust-rkyv0.7+std-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+strict-devel", rpm:"rust-rkyv0.7+strict-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7+validation-devel", rpm:"rust-rkyv0.7+validation-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7", rpm:"rust-rkyv0.7~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv0.7-devel", rpm:"rust-rkyv0.7-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv_derive0.7+arbitrary_enum_discriminant-devel", rpm:"rust-rkyv_derive0.7+arbitrary_enum_discriminant-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv_derive0.7+archive_be-devel", rpm:"rust-rkyv_derive0.7+archive_be-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv_derive0.7+archive_le-devel", rpm:"rust-rkyv_derive0.7+archive_le-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv_derive0.7+copy-devel", rpm:"rust-rkyv_derive0.7+copy-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv_derive0.7+default-devel", rpm:"rust-rkyv_derive0.7+default-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv_derive0.7+strict-devel", rpm:"rust-rkyv_derive0.7+strict-devel~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv_derive0.7", rpm:"rust-rkyv_derive0.7~0.7.46~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rkyv_derive0.7-devel", rpm:"rust-rkyv_derive0.7-devel~0.7.46~1.fc42", rls:"FC42"))) {
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
