# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.9988156992979");
  script_cve_id("CVE-2025-15269", "CVE-2025-15275", "CVE-2025-15279");
  script_tag(name:"creation_date", value:"2026-02-02 04:44:26 +0000 (Mon, 02 Feb 2026)");
  script_version("2026-02-02T05:59:28+0000");
  script_tag(name:"last_modification", value:"2026-02-02 05:59:28 +0000 (Mon, 02 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-9b8156c2a9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-9b8156c2a9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-9b8156c2a9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2426577");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2426589");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2426593");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fontforge' package(s) announced via the FEDORA-2026-9b8156c2a9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Resolves: CVE-2025-15279, CVE-2025-15275, CVE-2025-15269");

  script_tag(name:"affected", value:"'fontforge' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"fontforge", rpm:"fontforge~20230101~18.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fontforge-debuginfo", rpm:"fontforge-debuginfo~20230101~18.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fontforge-debugsource", rpm:"fontforge-debugsource~20230101~18.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fontforge-devel", rpm:"fontforge-devel~20230101~18.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fontforge-doc", rpm:"fontforge-doc~20230101~18.fc42", rls:"FC42"))) {
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
