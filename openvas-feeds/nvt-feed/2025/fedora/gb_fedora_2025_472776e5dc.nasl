# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2025.472776101510099");
  script_cve_id("CVE-2025-3416");
  script_tag(name:"creation_date", value:"2025-04-18 04:04:42 +0000 (Fri, 18 Apr 2025)");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-04-08 19:15:53 +0000 (Tue, 08 Apr 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2025-472776e5dc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2025-472776e5dc");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2025-472776e5dc");
  script_xref(name:"URL", value:"https://rustsec.org/advisories/RUSTSEC-2025-0022.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-openssl, rust-openssl-sys' package(s) announced via the FEDORA-2025-472776e5dc advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Update the openssl crate to version 0.10.72.
- Update the openssl-sys crate to version 0.9.107.

This update addresses [CVE-2025-3416]([link moved to references]) / [RUSTSEC-2025-0022]([link moved to references]) (a possible use-after-free issue in two public functions). A survey of dependent packages in Fedora shows that none of them use the affected API, or do not use them in a way that triggers this issue.");

  script_tag(name:"affected", value:"'rust-openssl, rust-openssl-sys' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl+bindgen-devel", rpm:"rust-openssl+bindgen-devel~0.10.72~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl+default-devel", rpm:"rust-openssl+default-devel~0.10.72~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl+v101-devel", rpm:"rust-openssl+v101-devel~0.10.72~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl+v102-devel", rpm:"rust-openssl+v102-devel~0.10.72~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl+v110-devel", rpm:"rust-openssl+v110-devel~0.10.72~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl+v111-devel", rpm:"rust-openssl+v111-devel~0.10.72~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl", rpm:"rust-openssl~0.10.72~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl-devel", rpm:"rust-openssl-devel~0.10.72~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl-sys+bindgen-devel", rpm:"rust-openssl-sys+bindgen-devel~0.9.107~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl-sys+default-devel", rpm:"rust-openssl-sys+default-devel~0.9.107~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl-sys", rpm:"rust-openssl-sys~0.9.107~1.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-openssl-sys-devel", rpm:"rust-openssl-sys-devel~0.9.107~1.fc40", rls:"FC40"))) {
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
