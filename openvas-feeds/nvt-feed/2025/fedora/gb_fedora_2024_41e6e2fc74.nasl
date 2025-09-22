# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.41101610121029974");
  script_cve_id("CVE-2024-11249");
  script_tag(name:"creation_date", value:"2025-05-26 07:22:06 +0000 (Mon, 26 May 2025)");
  script_version("2025-05-27T05:40:43+0000");
  script_tag(name:"last_modification", value:"2025-05-27 05:40:43 +0000 (Tue, 27 May 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-41e6e2fc74)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC41");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-41e6e2fc74");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-41e6e2fc74");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2326414");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-rustls, rust-zlib-rs' package(s) announced via the FEDORA-2024-41e6e2fc74 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update the rustls crate to version 0.23.17.
- Update the zlib-rs crate to version 0.4.0.

The update to zlib-rs v0.4.0 also addresses CVE-2024-11249 (stack overflow during decompression with malicious input). This issue had no actual impact in Fedora, because no applications yet use the the zlib-rs feature of rustls and rustls is the only dependent package of zlib-rs.");

  script_tag(name:"affected", value:"'rust-rustls, rust-zlib-rs' package(s) on Fedora 41.");

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

if(release == "FC41") {

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+brotli-devel", rpm:"rust-rustls+brotli-devel~0.23.17~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+custom-provider-devel", rpm:"rust-rustls+custom-provider-devel~0.23.17~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+default-devel", rpm:"rust-rustls+default-devel~0.23.17~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+hashbrown-devel", rpm:"rust-rustls+hashbrown-devel~0.23.17~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+log-devel", rpm:"rust-rustls+log-devel~0.23.17~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+logging-devel", rpm:"rust-rustls+logging-devel~0.23.17~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+read_buf-devel", rpm:"rust-rustls+read_buf-devel~0.23.17~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+ring-devel", rpm:"rust-rustls+ring-devel~0.23.17~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+rustversion-devel", rpm:"rust-rustls+rustversion-devel~0.23.17~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+std-devel", rpm:"rust-rustls+std-devel~0.23.17~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+tls12-devel", rpm:"rust-rustls+tls12-devel~0.23.17~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls+zlib-devel", rpm:"rust-rustls+zlib-devel~0.23.17~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls", rpm:"rust-rustls~0.23.17~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rustls-devel", rpm:"rust-rustls-devel~0.23.17~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zlib-rs+c-allocator-devel", rpm:"rust-zlib-rs+c-allocator-devel~0.4.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zlib-rs+default-devel", rpm:"rust-zlib-rs+default-devel~0.4.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zlib-rs+rust-allocator-devel", rpm:"rust-zlib-rs+rust-allocator-devel~0.4.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zlib-rs+std-devel", rpm:"rust-zlib-rs+std-devel~0.4.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zlib-rs", rpm:"rust-zlib-rs~0.4.0~1.fc41", rls:"FC41"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-zlib-rs-devel", rpm:"rust-zlib-rs-devel~0.4.0~1.fc41", rls:"FC41"))) {
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
