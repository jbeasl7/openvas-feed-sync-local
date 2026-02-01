# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.810101017859772");
  script_cve_id("CVE-2025-12084");
  script_tag(name:"creation_date", value:"2026-01-19 04:27:49 +0000 (Mon, 19 Jan 2026)");
  script_version("2026-01-19T05:50:51+0000");
  script_tag(name:"last_modification", value:"2026-01-19 05:50:51 +0000 (Mon, 19 Jan 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-12-16 21:13:09 +0000 (Tue, 16 Dec 2025)");

  script_name("Fedora: Security Advisory (FEDORA-2026-8e0e785a72)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-8e0e785a72");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-8e0e785a72");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2421612");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.12' package(s) announced via the FEDORA-2026-8e0e785a72 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Security fix for CVE-2025-12084
- Require at least the same expat version as used during the build time");

  script_tag(name:"affected", value:"'python3.12' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"python3.12", rpm:"python3.12~3.12.12~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-debug", rpm:"python3.12-debug~3.12.12~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-debuginfo", rpm:"python3.12-debuginfo~3.12.12~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-debugsource", rpm:"python3.12-debugsource~3.12.12~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-devel", rpm:"python3.12-devel~3.12.12~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-idle", rpm:"python3.12-idle~3.12.12~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-libs", rpm:"python3.12-libs~3.12.12~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-test", rpm:"python3.12-test~3.12.12~2.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-tkinter", rpm:"python3.12-tkinter~3.12.12~2.fc42", rls:"FC42"))) {
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
