# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.3053.1");
  script_cve_id("CVE-2016-9434", "CVE-2016-9435", "CVE-2016-9436", "CVE-2016-9437", "CVE-2016-9438", "CVE-2016-9439", "CVE-2016-9440", "CVE-2016-9441", "CVE-2016-9442", "CVE-2016-9443", "CVE-2016-9621", "CVE-2016-9622", "CVE-2016-9623", "CVE-2016-9624", "CVE-2016-9625", "CVE-2016-9626", "CVE-2016-9627", "CVE-2016-9628", "CVE-2016-9629", "CVE-2016-9630", "CVE-2016-9631", "CVE-2016-9632", "CVE-2016-9633");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-13 18:03:25 +0000 (Tue, 13 Dec 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:3053-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:3053-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20163053-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011283");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011284");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011285");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011286");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011287");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011289");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011290");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011291");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011292");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1011293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012021");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012023");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012024");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012025");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012026");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012027");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012029");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012030");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012031");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1012032");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-December/002454.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'w3m' package(s) announced via the SUSE-SU-2016:3053-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for w3m fixes the following issues:

- update to debian git version (bsc#1011293)
 addressed security issues:
 CVE-2016-9622: w3m: null deref (bsc#1012021)
 CVE-2016-9623: w3m: null deref (bsc#1012022)
 CVE-2016-9624: w3m: near-null deref (bsc#1012023)
 CVE-2016-9625: w3m: stack overflow (bsc#1012024)
 CVE-2016-9626: w3m: stack overflow (bsc#1012025)
 CVE-2016-9627: w3m: heap overflow read + deref (bsc#1012026)
 CVE-2016-9628: w3m: null deref (bsc#1012027)
 CVE-2016-9629: w3m: null deref (bsc#1012028)
 CVE-2016-9630: w3m: global-buffer-overflow read (bsc#1012029)
 CVE-2016-9631: w3m: null deref (bsc#1012030)
 CVE-2016-9632: w3m: global-buffer-overflow read (bsc#1012031)
 CVE-2016-9633: w3m: OOM (bsc#1012032)
 CVE-2016-9434: w3m: null deref (bsc#1011283)
 CVE-2016-9435: w3m: use uninit value (bsc#1011284)
 CVE-2016-9436: w3m: use uninit value (bsc#1011285)
 CVE-2016-9437: w3m: write to rodata (bsc#1011286)
 CVE-2016-9438: w3m: null deref (bsc#1011287)
 CVE-2016-9439: w3m: stack overflow (bsc#1011288)
 CVE-2016-9440: w3m: near-null deref (bsc#1011289)
 CVE-2016-9441: w3m: near-null deref (bsc#1011290)
 CVE-2016-9442: w3m: potential heap buffer corruption (bsc#1011291)
 CVE-2016-9443: w3m: null deref (bsc#1011292)");

  script_tag(name:"affected", value:"'w3m' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.3.git20161120~160.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.3.git20161120~160.1", rls:"SLES12.0SP2"))) {
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
