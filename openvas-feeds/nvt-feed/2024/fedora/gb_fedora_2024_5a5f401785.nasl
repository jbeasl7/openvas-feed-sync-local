# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.5975102401785");
  script_tag(name:"creation_date", value:"2024-12-11 08:40:14 +0000 (Wed, 11 Dec 2024)");
  script_version("2024-12-12T09:30:20+0000");
  script_tag(name:"last_modification", value:"2024-12-12 09:30:20 +0000 (Thu, 12 Dec 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-5a5f401785)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-5a5f401785");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-5a5f401785");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2024-0399.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-rustls' package(s) announced via the FEDORA-2024-5a5f401785 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to version 0.23.19.

This version includes fix for [RUSTSEC-2024-0399]([link moved to references]).");

  script_tag(name:"affected", value:"'rust-rustls' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+brotli-devel", rpm:"rust-rustls+brotli-devel~0.23.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+custom-provider-devel", rpm:"rust-rustls+custom-provider-devel~0.23.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+default-devel", rpm:"rust-rustls+default-devel~0.23.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+hashbrown-devel", rpm:"rust-rustls+hashbrown-devel~0.23.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+log-devel", rpm:"rust-rustls+log-devel~0.23.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+logging-devel", rpm:"rust-rustls+logging-devel~0.23.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+read_buf-devel", rpm:"rust-rustls+read_buf-devel~0.23.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+ring-devel", rpm:"rust-rustls+ring-devel~0.23.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+rustversion-devel", rpm:"rust-rustls+rustversion-devel~0.23.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+std-devel", rpm:"rust-rustls+std-devel~0.23.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+tls12-devel", rpm:"rust-rustls+tls12-devel~0.23.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+zlib-devel", rpm:"rust-rustls+zlib-devel~0.23.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls", rpm:"rust-rustls~0.23.19~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls-devel", rpm:"rust-rustls-devel~0.23.19~1.fc40", rls:"FC40"))) {
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
