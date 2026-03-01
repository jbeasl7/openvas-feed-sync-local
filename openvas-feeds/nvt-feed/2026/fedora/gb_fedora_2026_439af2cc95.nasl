# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2026.439971022999995");
  script_cve_id("CVE-2025-65637");
  script_tag(name:"creation_date", value:"2026-02-19 04:40:27 +0000 (Thu, 19 Feb 2026)");
  script_version("2026-02-19T05:56:52+0000");
  script_tag(name:"last_modification", value:"2026-02-19 05:56:52 +0000 (Thu, 19 Feb 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2026-439af2cc95)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC42");

  script_xref(name:"Advisory-ID", value:"FEDORA-2026-439af2cc95");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2026-439af2cc95");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2422175");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2422195");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fvwm3' package(s) announced via the FEDORA-2026-439af2cc95 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Fix CVE-2025-65637.");

  script_tag(name:"affected", value:"'fvwm3' package(s) on Fedora 42.");

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

  if(!isnull(res = isrpmvuln(pkg:"fvwm3", rpm:"fvwm3~1.1.4~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fvwm3-debuginfo", rpm:"fvwm3-debuginfo~1.1.4~4.fc42", rls:"FC42"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fvwm3-debugsource", rpm:"fvwm3-debugsource~1.1.4~4.fc42", rls:"FC42"))) {
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
