# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0663.1");
  script_cve_id("CVE-2025-15366", "CVE-2025-15367", "CVE-2025-6075", "CVE-2026-0672", "CVE-2026-0865");
  script_tag(name:"creation_date", value:"2026-03-02 04:37:24 +0000 (Mon, 02 Mar 2026)");
  script_version("2026-03-02T05:55:30+0000");
  script_tag(name:"last_modification", value:"2026-03-02 05:55:30 +0000 (Mon, 02 Mar 2026)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2026-02-04 18:46:13 +0000 (Wed, 04 Feb 2026)");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0663-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0663-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260663-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1252974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1254867");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257042");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257044");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1257064");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-February/024447.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python' package(s) announced via the SUSE-SU-2026:0663-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python fixes the following issues:

- CVE-2025-6075: Fixed performance degradation when using os.path.expandvars() (bsc#1252974).
- CVE-2026-0672: Fixed a HTTP header injection via user-controlled cookie values and parameters when using http.cookies.Morsel. (bsc#1257031)
- CVE-2026-0865: Fixed a bug where a user-controlled header containing newlines can allow injecting HTTP headers. (bsc#1257042)
- CVE-2025-15366: Fixed a bug wherer a user-controlled command can allow additional commands injected using newlines. (bsc#1257044)
- CVE-2025-15367: Fixed control characters which may allow the injection of additional commands. (bsc#1257041)");

  script_tag(name:"affected", value:"'python' package(s) on SUSE Linux Enterprise Server 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0", rpm:"libpython2_7-1_0~2.7.18~33.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2_7-1_0-32bit", rpm:"libpython2_7-1_0-32bit~2.7.18~33.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.7.18~33.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-32bit", rpm:"python-32bit~2.7.18~33.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base", rpm:"python-base~2.7.18~33.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-base-32bit", rpm:"python-base-32bit~2.7.18~33.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-curses", rpm:"python-curses~2.7.18~33.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-demo", rpm:"python-demo~2.7.18~33.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.7.18~33.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-doc", rpm:"python-doc~2.7.18~33.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-doc-pdf", rpm:"python-doc-pdf~2.7.18~33.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gdbm", rpm:"python-gdbm~2.7.18~33.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-idle", rpm:"python-idle~2.7.18~33.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-tk", rpm:"python-tk~2.7.18~33.63.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-xml", rpm:"python-xml~2.7.18~33.63.1", rls:"SLES12.0SP5"))) {
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
