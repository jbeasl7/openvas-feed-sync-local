# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.9791009985091019");
  script_cve_id("CVE-2025-64505", "CVE-2025-64506", "CVE-2025-64720", "CVE-2025-65018", "CVE-2025-66293");
  script_tag(name:"creation_date", value:"2026-01-12 04:26:16 +0000 (Mon, 12 Jan 2026)");
  script_version("2026-01-12T05:50:06+0000");
  script_tag(name:"last_modification", value:"2026-01-12 05:50:06 +0000 (Mon, 12 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-a9dc8509e9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-a9dc8509e9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-a9dc8509e9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2417429");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2417448");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2417459");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2418410");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2418736");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng' package(s) announced via the FEDORA-2026-a9dc8509e9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"fixes several security issues");

  script_tag(name:"affected", value:"'libpng' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.6.53~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-debuginfo", rpm:"libpng-debuginfo~1.6.53~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-debugsource", rpm:"libpng-debugsource~1.6.53~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.6.53~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-devel-debuginfo", rpm:"libpng-devel-debuginfo~1.6.53~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-static", rpm:"libpng-static~1.6.53~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-tools", rpm:"libpng-tools~1.6.53~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpng-tools-debuginfo", rpm:"libpng-tools-debuginfo~1.6.53~1.fc42", rls:"FC42"))) {
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
