# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0644.1");
  script_cve_id("CVE-2025-11468", "CVE-2025-15282", "CVE-2025-15366", "CVE-2025-15367", "CVE-2026-0672", "CVE-2026-0865");
  script_tag(name:"creation_date", value:"2026-03-02 04:37:24 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0644-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP6)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0644-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260644-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257046");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024403.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python312' package(s) announced via the SUSE-SU-2026:0644-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python312 fixes the following issues:

- CVE-2025-11468: header injection when folding a long comment in an email header containing exclusively unfoldable
 characters (bsc#1257029).
- CVE-2026-0672: HTTP header injection via user-controlled cookie values and parameters when using http.cookies.Morsel
 (bsc#1257031).
- CVE-2026-0865: user-controlled header containing newlines can allow injecting HTTP headers (bsc#1257042).
- CVE-2025-15366: user-controlled command can allow additional commands injected using newlines (bsc#1257044).
- CVE-2025-15282: user-controlled data URLs parsed may allow injecting headers (bsc#1257046).
- CVE-2025-15367: control characters may allow the injection of additional commands (bsc#1257041).");

  script_tag(name:"affected", value:"'python312' package(s) on SUSE Linux Enterprise Server 15-SP6, SUSE Linux Enterprise Server for SAP Applications 15-SP6.");

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

if(release == "SLES15.0SP6") {

  if(!isnull(res = isrpmvuln(pkg:"libpython3_12-1_0", rpm:"libpython3_12-1_0~3.12.12~150600.3.43.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312", rpm:"python312~3.12.12~150600.3.43.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-base", rpm:"python312-base~3.12.12~150600.3.43.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-curses", rpm:"python312-curses~3.12.12~150600.3.43.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-dbm", rpm:"python312-dbm~3.12.12~150600.3.43.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-devel", rpm:"python312-devel~3.12.12~150600.3.43.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-idle", rpm:"python312-idle~3.12.12~150600.3.43.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-tk", rpm:"python312-tk~3.12.12~150600.3.43.1", rls:"SLES15.0SP6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python312-tools", rpm:"python312-tools~3.12.12~150600.3.43.1", rls:"SLES15.0SP6"))) {
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
