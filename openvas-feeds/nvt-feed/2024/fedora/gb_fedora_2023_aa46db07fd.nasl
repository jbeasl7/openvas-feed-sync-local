# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.9797461009807102100");
  script_cve_id("CVE-2023-28626", "CVE-2023-28631");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-06 18:03:26 +0000 (Thu, 06 Apr 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-aa46db07fd)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-aa46db07fd");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-aa46db07fd");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2094154");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184923");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2184926");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-askama, rust-askama_shared, rust-comrak' package(s) announced via the FEDORA-2023-aa46db07fd advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update comrak to version 0.18.0.
- Disable the unused markdown support in askama and askama_shared crates, which depends on an ancient version of comrak.

This update also includes fixes for two medium-severity security issues in comrak (CVE-2023-28631 and CVE-2023-28626).");

  script_tag(name:"affected", value:"'rust-askama, rust-askama_shared, rust-comrak' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"comrak", rpm:"comrak~0.18.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"comrak-debuginfo", rpm:"comrak-debuginfo~0.18.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+config-devel", rpm:"rust-askama+config-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+default-devel", rpm:"rust-askama+default-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+humansize-devel", rpm:"rust-askama+humansize-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+mime-devel", rpm:"rust-askama+mime-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+mime_guess-devel", rpm:"rust-askama+mime_guess-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+num-traits-devel", rpm:"rust-askama+num-traits-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+serde-json-devel", rpm:"rust-askama+serde-json-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+serde-yaml-devel", rpm:"rust-askama+serde-yaml-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+urlencode-devel", rpm:"rust-askama+urlencode-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+with-actix-web-devel", rpm:"rust-askama+with-actix-web-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+with-axum-devel", rpm:"rust-askama+with-axum-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+with-gotham-devel", rpm:"rust-askama+with-gotham-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+with-mendes-devel", rpm:"rust-askama+with-mendes-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+with-rocket-devel", rpm:"rust-askama+with-rocket-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+with-tide-devel", rpm:"rust-askama+with-tide-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama+with-warp-devel", rpm:"rust-askama+with-warp-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama", rpm:"rust-askama~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama-devel", rpm:"rust-askama-devel~0.11.1~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama_shared+config-devel", rpm:"rust-askama_shared+config-devel~0.12.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama_shared+default-devel", rpm:"rust-askama_shared+default-devel~0.12.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama_shared+humansize-devel", rpm:"rust-askama_shared+humansize-devel~0.12.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama_shared+json-devel", rpm:"rust-askama_shared+json-devel~0.12.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama_shared+num-traits-devel", rpm:"rust-askama_shared+num-traits-devel~0.12.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama_shared+percent-encoding-devel", rpm:"rust-askama_shared+percent-encoding-devel~0.12.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama_shared+serde-devel", rpm:"rust-askama_shared+serde-devel~0.12.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama_shared+serde_json-devel", rpm:"rust-askama_shared+serde_json-devel~0.12.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama_shared+serde_yaml-devel", rpm:"rust-askama_shared+serde_yaml-devel~0.12.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama_shared+toml-devel", rpm:"rust-askama_shared+toml-devel~0.12.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama_shared+yaml-devel", rpm:"rust-askama_shared+yaml-devel~0.12.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama_shared", rpm:"rust-askama_shared~0.12.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-askama_shared-devel", rpm:"rust-askama_shared-devel~0.12.2~4.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak+clap-devel", rpm:"rust-comrak+clap-devel~0.18.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak+cli-devel", rpm:"rust-comrak+cli-devel~0.18.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak+default-devel", rpm:"rust-comrak+default-devel~0.18.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak+shell-words-devel", rpm:"rust-comrak+shell-words-devel~0.18.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak+syntect-devel", rpm:"rust-comrak+syntect-devel~0.18.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak+xdg-devel", rpm:"rust-comrak+xdg-devel~0.18.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak", rpm:"rust-comrak~0.18.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak-debugsource", rpm:"rust-comrak-debugsource~0.18.0~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-comrak-devel", rpm:"rust-comrak-devel~0.18.0~1.fc39", rls:"FC39"))) {
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
