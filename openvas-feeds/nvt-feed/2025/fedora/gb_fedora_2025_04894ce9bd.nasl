# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.0489499101998100");
  script_cve_id("CVE-2025-4574");
  script_tag(name:"creation_date", value:"2025-05-30 04:06:29 +0000 (Fri, 30 May 2025)");
  script_version("2025-05-30T05:40:08+0000");
  script_tag(name:"last_modification", value:"2025-05-30 05:40:08 +0000 (Fri, 30 May 2025)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-05-13 22:15:25 +0000 (Tue, 13 May 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-04894ce9bd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-04894ce9bd");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-04894ce9bd");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2331134");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2366571");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruff, rust-hashlink, rust-rusqlite' package(s) announced via the FEDORA-2025-04894ce9bd advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Security update for CVE-2025-4574, GHSA-pg9f-39pc-qf8g: by rebuilding `ruff`, we ensure that it uses version 0.5.15 of the `crossbeam-channel` crate library.

-----

## `rust-hashlink` 0.10.0

- API incompatible change: upgrade `hashbrown` to 0.15
- API incompatible change: we now wrap `DefaultHashBuilder` and `DefaultHasher`
 from `hashbrown` so that in the future upgrading `hashbrown` is not an API
 incompatible change");

  script_tag(name:"affected", value:"'ruff, rust-hashlink, rust-rusqlite' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"ruff", rpm:"ruff~0.11.5~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruff-debuginfo", rpm:"ruff-debuginfo~0.11.5~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruff-debugsource", rpm:"ruff-debugsource~0.11.5~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hashlink+default-devel", rpm:"rust-hashlink+default-devel~0.10.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hashlink+serde-devel", rpm:"rust-hashlink+serde-devel~0.10.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hashlink+serde_impl-devel", rpm:"rust-hashlink+serde_impl-devel~0.10.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hashlink", rpm:"rust-hashlink~0.10.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-hashlink-devel", rpm:"rust-hashlink-devel~0.10.0~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+array-devel", rpm:"rust-rusqlite+array-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+backup-devel", rpm:"rust-rusqlite+backup-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+blob-devel", rpm:"rust-rusqlite+blob-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+buildtime_bindgen-devel", rpm:"rust-rusqlite+buildtime_bindgen-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+chrono-devel", rpm:"rust-rusqlite+chrono-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+collation-devel", rpm:"rust-rusqlite+collation-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+column_decltype-devel", rpm:"rust-rusqlite+column_decltype-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+csv-devel", rpm:"rust-rusqlite+csv-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+csvtab-devel", rpm:"rust-rusqlite+csvtab-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+default-devel", rpm:"rust-rusqlite+default-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+extra_check-devel", rpm:"rust-rusqlite+extra_check-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+functions-devel", rpm:"rust-rusqlite+functions-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+hooks-devel", rpm:"rust-rusqlite+hooks-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+i128_blob-devel", rpm:"rust-rusqlite+i128_blob-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+limits-devel", rpm:"rust-rusqlite+limits-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+load_extension-devel", rpm:"rust-rusqlite+load_extension-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+modern-full-devel", rpm:"rust-rusqlite+modern-full-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+modern_sqlite-devel", rpm:"rust-rusqlite+modern_sqlite-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+release_memory-devel", rpm:"rust-rusqlite+release_memory-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+serde_json-devel", rpm:"rust-rusqlite+serde_json-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+serialize-devel", rpm:"rust-rusqlite+serialize-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+series-devel", rpm:"rust-rusqlite+series-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+session-devel", rpm:"rust-rusqlite+session-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+time-devel", rpm:"rust-rusqlite+time-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+trace-devel", rpm:"rust-rusqlite+trace-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+unlock_notify-devel", rpm:"rust-rusqlite+unlock_notify-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+url-devel", rpm:"rust-rusqlite+url-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+uuid-devel", rpm:"rust-rusqlite+uuid-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+vtab-devel", rpm:"rust-rusqlite+vtab-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite+window-devel", rpm:"rust-rusqlite+window-devel~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite", rpm:"rust-rusqlite~0.31.0~6.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-rusqlite-devel", rpm:"rust-rusqlite-devel~0.31.0~6.fc42", rls:"FC42"))) {
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
