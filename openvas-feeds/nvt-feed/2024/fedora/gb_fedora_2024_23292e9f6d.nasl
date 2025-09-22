# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2024.2329210191026100");
  script_tag(name:"creation_date", value:"2024-10-24 04:08:58 +0000 (Thu, 24 Oct 2024)");
  script_version("2024-10-25T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-10-25 05:05:38 +0000 (Fri, 25 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-23292e9f6d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-23292e9f6d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-23292e9f6d");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2024-0378.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-pyo3, rust-pyo3-build-config, rust-pyo3-ffi, rust-pyo3-macros, rust-pyo3-macros-backend' package(s) announced via the FEDORA-2024-23292e9f6d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update pyo3 to version 0.22.4.

This version addresses a potential use-after-free [RUSTSEC-2024-0378]([link moved to references]).");

  script_tag(name:"affected", value:"'rust-pyo3, rust-pyo3-build-config, rust-pyo3-ffi, rust-pyo3-macros, rust-pyo3-macros-backend' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+abi3-devel", rpm:"rust-pyo3+abi3-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+abi3-py310-devel", rpm:"rust-pyo3+abi3-py310-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+abi3-py311-devel", rpm:"rust-pyo3+abi3-py311-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+abi3-py312-devel", rpm:"rust-pyo3+abi3-py312-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+abi3-py37-devel", rpm:"rust-pyo3+abi3-py37-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+abi3-py38-devel", rpm:"rust-pyo3+abi3-py38-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+abi3-py39-devel", rpm:"rust-pyo3+abi3-py39-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+anyhow-devel", rpm:"rust-pyo3+anyhow-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+auto-initialize-devel", rpm:"rust-pyo3+auto-initialize-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+chrono-devel", rpm:"rust-pyo3+chrono-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+chrono-tz-devel", rpm:"rust-pyo3+chrono-tz-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+default-devel", rpm:"rust-pyo3+default-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+either-devel", rpm:"rust-pyo3+either-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+experimental-async-devel", rpm:"rust-pyo3+experimental-async-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+experimental-inspect-devel", rpm:"rust-pyo3+experimental-inspect-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+extension-module-devel", rpm:"rust-pyo3+extension-module-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+eyre-devel", rpm:"rust-pyo3+eyre-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+full-devel", rpm:"rust-pyo3+full-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+gil-refs-devel", rpm:"rust-pyo3+gil-refs-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+hashbrown-devel", rpm:"rust-pyo3+hashbrown-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+indexmap-devel", rpm:"rust-pyo3+indexmap-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+indoc-devel", rpm:"rust-pyo3+indoc-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+inventory-devel", rpm:"rust-pyo3+inventory-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+macros-devel", rpm:"rust-pyo3+macros-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+multiple-pymethods-devel", rpm:"rust-pyo3+multiple-pymethods-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+nightly-devel", rpm:"rust-pyo3+nightly-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+num-bigint-devel", rpm:"rust-pyo3+num-bigint-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+num-complex-devel", rpm:"rust-pyo3+num-complex-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+num-rational-devel", rpm:"rust-pyo3+num-rational-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+py-clone-devel", rpm:"rust-pyo3+py-clone-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+pyo3-macros-devel", rpm:"rust-pyo3+pyo3-macros-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+rust_decimal-devel", rpm:"rust-pyo3+rust_decimal-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+serde-devel", rpm:"rust-pyo3+serde-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+smallvec-devel", rpm:"rust-pyo3+smallvec-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3+unindent-devel", rpm:"rust-pyo3+unindent-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3", rpm:"rust-pyo3~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-build-config+abi3-devel", rpm:"rust-pyo3-build-config+abi3-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-build-config+abi3-py310-devel", rpm:"rust-pyo3-build-config+abi3-py310-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-build-config+abi3-py311-devel", rpm:"rust-pyo3-build-config+abi3-py311-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-build-config+abi3-py312-devel", rpm:"rust-pyo3-build-config+abi3-py312-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-build-config+abi3-py37-devel", rpm:"rust-pyo3-build-config+abi3-py37-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-build-config+abi3-py38-devel", rpm:"rust-pyo3-build-config+abi3-py38-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-build-config+abi3-py39-devel", rpm:"rust-pyo3-build-config+abi3-py39-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-build-config+default-devel", rpm:"rust-pyo3-build-config+default-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-build-config+extension-module-devel", rpm:"rust-pyo3-build-config+extension-module-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-build-config+resolve-config-devel", rpm:"rust-pyo3-build-config+resolve-config-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-build-config", rpm:"rust-pyo3-build-config~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-build-config-devel", rpm:"rust-pyo3-build-config-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-devel", rpm:"rust-pyo3-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-ffi+abi3-devel", rpm:"rust-pyo3-ffi+abi3-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-ffi+abi3-py310-devel", rpm:"rust-pyo3-ffi+abi3-py310-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-ffi+abi3-py311-devel", rpm:"rust-pyo3-ffi+abi3-py311-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-ffi+abi3-py312-devel", rpm:"rust-pyo3-ffi+abi3-py312-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-ffi+abi3-py37-devel", rpm:"rust-pyo3-ffi+abi3-py37-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-ffi+abi3-py38-devel", rpm:"rust-pyo3-ffi+abi3-py38-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-ffi+abi3-py39-devel", rpm:"rust-pyo3-ffi+abi3-py39-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-ffi+default-devel", rpm:"rust-pyo3-ffi+default-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-ffi+extension-module-devel", rpm:"rust-pyo3-ffi+extension-module-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-ffi", rpm:"rust-pyo3-ffi~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-ffi-devel", rpm:"rust-pyo3-ffi-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-macros+default-devel", rpm:"rust-pyo3-macros+default-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-macros+experimental-async-devel", rpm:"rust-pyo3-macros+experimental-async-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-macros+gil-refs-devel", rpm:"rust-pyo3-macros+gil-refs-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-macros+multiple-pymethods-devel", rpm:"rust-pyo3-macros+multiple-pymethods-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-macros", rpm:"rust-pyo3-macros~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-macros-backend+default-devel", rpm:"rust-pyo3-macros-backend+default-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-macros-backend+experimental-async-devel", rpm:"rust-pyo3-macros-backend+experimental-async-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-macros-backend+gil-refs-devel", rpm:"rust-pyo3-macros-backend+gil-refs-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-macros-backend", rpm:"rust-pyo3-macros-backend~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-macros-backend-devel", rpm:"rust-pyo3-macros-backend-devel~0.22.4~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-pyo3-macros-devel", rpm:"rust-pyo3-macros-devel~0.22.4~1.fc40", rls:"FC40"))) {
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
