# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2026.0800.1");
  script_cve_id("CVE-2026-28364");
  script_tag(name:"creation_date", value:"2026-03-06 04:34:54 +0000 (Fri, 06 Mar 2026)");
  script_version("2026-03-06T15:49:04+0000");
  script_tag(name:"last_modification", value:"2026-03-06 15:49:04 +0000 (Fri, 06 Mar 2026)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2026:0800-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2026 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4|SLES15\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2026:0800-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2026/suse-su-20260800-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1258992");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2026-March/024571.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ocaml' package(s) announced via the SUSE-SU-2026:0800-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ocaml fixes the following issues:

- CVE-2026-28364: missing bounds validation in readblock() can lead to arbitrary code execution (bsc#1258992).");

  script_tag(name:"affected", value:"'ocaml' package(s) on SUSE Linux Enterprise Server 15-SP4, SUSE Linux Enterprise Server 15-SP5, SUSE Linux Enterprise Server for SAP Applications 15-SP4, SUSE Linux Enterprise Server for SAP Applications 15-SP5.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"ocaml", rpm:"ocaml~4.05.0~150200.15.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-compiler-libs", rpm:"ocaml-compiler-libs~4.05.0~150200.15.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-compiler-libs-devel", rpm:"ocaml-compiler-libs-devel~4.05.0~150200.15.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-ocamldoc", rpm:"ocaml-ocamldoc~4.05.0~150200.15.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-runtime", rpm:"ocaml-runtime~4.05.0~150200.15.3.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"ocaml", rpm:"ocaml~4.05.0~150200.15.3.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-compiler-libs", rpm:"ocaml-compiler-libs~4.05.0~150200.15.3.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-compiler-libs-devel", rpm:"ocaml-compiler-libs-devel~4.05.0~150200.15.3.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-ocamldoc", rpm:"ocaml-ocamldoc~4.05.0~150200.15.3.1", rls:"SLES15.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ocaml-runtime", rpm:"ocaml-runtime~4.05.0~150200.15.3.1", rls:"SLES15.0SP5"))) {
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
