# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.510271000975656");
  script_cve_id("CVE-2025-11187", "CVE-2025-15467", "CVE-2025-15468", "CVE-2025-15469", "CVE-2025-66199", "CVE-2025-68160", "CVE-2025-69418", "CVE-2025-69419", "CVE-2025-69420", "CVE-2025-69421", "CVE-2026-22795", "CVE-2026-22796");
  script_tag(name:"creation_date", value:"2026-02-02 04:44:26 +0000 (Mon, 02 Feb 2026)");
  script_version("2026-02-02T05:59:28+0000");
  script_tag(name:"last_modification", value:"2026-02-02 05:59:28 +0000 (Mon, 02 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-5f7d0a5656)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC43");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-5f7d0a5656");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-5f7d0a5656");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the FEDORA-2026-5f7d0a5656 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Resolves: CVE-2025-15467
Resolves: CVE-2025-15468
Resolves: CVE-2025-15469
Resolves: CVE-2025-66199
Resolves: CVE-2025-68160
Resolves: CVE-2025-69418
Resolves: CVE-2025-69420
Resolves: CVE-2025-69421
Resolves: CVE-2025-69419
Resolves: CVE-2026-22795
Resolves: CVE-2026-22796
Resolves: CVE-2025-11187");

  script_tag(name:"affected", value:"'openssl' package(s) on Fedora 43.");

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

if(release == "FC43") {

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~3.5.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-debuginfo", rpm:"openssl-debuginfo~3.5.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-debugsource", rpm:"openssl-debugsource~3.5.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel", rpm:"openssl-devel~3.5.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-devel-engine", rpm:"openssl-devel-engine~3.5.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-libs", rpm:"openssl-libs~3.5.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-libs-debuginfo", rpm:"openssl-libs-debuginfo~3.5.4~2.fc43", rls:"FC43"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-perl", rpm:"openssl-perl~3.5.4~2.fc43", rls:"FC43"))) {
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
