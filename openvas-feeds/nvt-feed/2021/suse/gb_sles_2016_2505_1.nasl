# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2016.2505.1");
  script_cve_id("CVE-2016-5407", "CVE-2016-7942", "CVE-2016-7944", "CVE-2016-7945", "CVE-2016-7946", "CVE-2016-7947", "CVE-2016-7948", "CVE-2016-7949", "CVE-2016-7950", "CVE-2016-7951", "CVE-2016-7952", "CVE-2016-7953");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-15 02:51:29 +0000 (Thu, 15 Dec 2016)");

  script_name("SUSE: Security Advisory (SUSE-SU-2016:2505-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2016:2505-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2016/suse-su-20162505-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002991");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1002998");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003000");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003002");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003012");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003017");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1003023");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2016-October/002323.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'X Window System client libraries' package(s) announced via the SUSE-SU-2016:2505-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the X Window System client libraries fixes a class of privilege escalation issues.

A malicious X Server could send specially crafted data to X clients, which allowed for triggering crashes, or privilege escalation if this relationship was untrusted or crossed user or permission level boundaries.

libX11, libXfixes, libXi, libXrandr, libXrender, libXtst, libXv, libXvMC were fixed, specifically:

libX11:
- CVE-2016-7942: insufficient validation of data from the X server allowed out of boundary memory read (bsc#1002991)

libXfixes:
- CVE-2016-7944: insufficient validation of data from the X server can cause an integer overflow on 32 bit architectures (bsc#1002995)

libXi:
- CVE-2016-7945, CVE-2016-7946: insufficient validation of data from the X server can cause out of boundary memory access or endless loops (Denial of Service) (bsc#1002998)

libXtst:
- CVE-2016-7951, CVE-2016-7952: insufficient validation of data from the X server can cause out of boundary memory access or endless loops (Denial of Service) (bsc#1003012)

libXv:
- CVE-2016-5407: insufficient validation of data from the X server can cause out of boundary memory and memory corruption (bsc#1003017)

libXvMC:
- CVE-2016-7953: insufficient validation of data from the X server can cause a one byte buffer read underrun (bsc#1003023)

libXrender:
- CVE-2016-7949, CVE-2016-7950: insufficient validation of data from the X server can cause out of boundary memory writes (bsc#1003002)

libXrandr:
- CVE-2016-7947, CVE-2016-7948: insufficient validation of data from the X server can cause out of boundary memory writes (bsc#1003000)");

  script_tag(name:"affected", value:"'X Window System client libraries' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"libX11-6", rpm:"libX11-6~1.6.2~6.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-6-32bit", rpm:"libX11-6-32bit~1.6.2~6.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-data", rpm:"libX11-data~1.6.2~6.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1", rpm:"libX11-xcb1~1.6.2~6.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libX11-xcb1-32bit", rpm:"libX11-xcb1-32bit~1.6.2~6.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXfixes3-32bit", rpm:"libXfixes3-32bit~5.0.1~5.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXfixes3", rpm:"libXfixes3~5.0.1~5.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXi6", rpm:"libXi6~1.7.4~12.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXi6-32bit", rpm:"libXi6-32bit~1.7.4~12.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXrandr2", rpm:"libXrandr2~1.4.2~5.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXrandr2-32bit", rpm:"libXrandr2-32bit~1.4.2~5.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXrender1", rpm:"libXrender1~0.9.8~5.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXrender1-32bit", rpm:"libXrender1-32bit~0.9.8~5.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXtst6", rpm:"libXtst6~1.2.2~5.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXtst6-32bit", rpm:"libXtst6-32bit~1.2.2~5.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXv1", rpm:"libXv1~1.0.10~5.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXv1-32bit", rpm:"libXv1-32bit~1.0.10~5.2", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libXvMC1", rpm:"libXvMC1~1.0.8~5.2", rls:"SLES12.0SP1"))) {
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
