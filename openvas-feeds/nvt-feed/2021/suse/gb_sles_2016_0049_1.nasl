# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.0049.1");
  script_cve_id("CVE-2015-1819", "CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8035", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:0049-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0|SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:0049-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20160049-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928193");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951734");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/951735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/954429");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/956260");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957106");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957107");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957109");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/957110");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-January/001788.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the SUSE-SU-2016:0049-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- security update:
 This update fixes the following security issues:

 * CVE-2015-1819 Enforce the reader to run in constant memory [bnc#928193]
 * CVE-2015-7941 Fix out of bound read with crafted xml input by stopping parsing on entities boundaries errors [bnc#951734]
 * CVE-2015-7942 Fix another variation of overflow in Conditional sections [bnc#951735]
 * CVE-2015-8241 Avoid extra processing of MarkupDecl when EOF [bnc#956018]
 * CVE-2015-8242 Buffer overead with HTML parser in push mode [bnc#956021]
 * CVE-2015-8317 Return if the encoding declaration is broken or encoding conversion failed [bnc#956260]
 * CVE-2015-5312 Fix another entity expansion issue [bnc#957105]
 * CVE-2015-7497 Avoid an heap buffer overflow in xmlDictComputeFastQKey [bnc#957106]
 * CVE-2015-7498 Processes entities after encoding conversion failures [bnc#957107]
 * CVE-2015-7499 Add xmlHaltParser() to stop the parser / Detect incoherency on GROW [bnc#957109]
 * CVE-2015-8317 Multiple out-of-bound read could lead to denial of service [bnc#956260]
 * CVE-2015-8035 DoS when parsing specially crafted XML document if XZ support is enabled [bnc#954429]
 * CVE-2015-7500 Fix memory access error due to incorrect entities boundaries [bnc#957110]");

  script_tag(name:"affected", value:"'libxml2' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.1~13.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.9.1~13.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-doc", rpm:"libxml2-doc~2.9.1~13.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.1~13.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2", rpm:"python-libxml2~2.9.1~13.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2", rpm:"libxml2-2~2.9.1~13.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-2-32bit", rpm:"libxml2-2-32bit~2.9.1~13.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-doc", rpm:"libxml2-doc~2.9.1~13.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-tools", rpm:"libxml2-tools~2.9.1~13.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-libxml2", rpm:"python-libxml2~2.9.1~13.1", rls:"SLES12.0SP1"))) {
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
