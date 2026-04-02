# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.31019810299129716");
  script_cve_id("CVE-2025-11468", "CVE-2025-15282", "CVE-2025-15366", "CVE-2025-15367", "CVE-2026-0672", "CVE-2026-0865", "CVE-2026-1299");
  script_tag(name:"creation_date", value:"2026-03-13 04:36:55 +0000 (Fri, 13 Mar 2026)");
  script_version("2026-03-13T15:49:08+0000");
  script_tag(name:"last_modification", value:"2026-03-13 15:49:08 +0000 (Fri, 13 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-3ebfc12a16)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-3ebfc12a16");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-3ebfc12a16");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431617");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431641");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431764");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431787");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431793");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2431808");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2433817");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.12' package(s) announced via the FEDORA-2026-3ebfc12a16 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 3.12.13

----

Security fixes for CVE-2026-1299, CVE-2026-0865, CVE-2025-15366 and CVE-2025-15367");

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

  if(!isnull(res = isrpmvuln(pkg:"python3.12", rpm:"python3.12~3.12.13~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-debug", rpm:"python3.12-debug~3.12.13~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-debuginfo", rpm:"python3.12-debuginfo~3.12.13~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-debugsource", rpm:"python3.12-debugsource~3.12.13~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-devel", rpm:"python3.12-devel~3.12.13~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-idle", rpm:"python3.12-idle~3.12.13~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-libs", rpm:"python3.12-libs~3.12.13~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-test", rpm:"python3.12-test~3.12.13~1.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3.12-tkinter", rpm:"python3.12-tkinter~3.12.13~1.fc42", rls:"FC42"))) {
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
