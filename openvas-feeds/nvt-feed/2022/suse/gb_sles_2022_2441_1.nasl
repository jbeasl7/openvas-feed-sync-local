# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2441.1");
  script_cve_id("CVE-2021-33430", "CVE-2021-41495", "CVE-2021-41496");
  script_tag(name:"creation_date", value:"2022-07-20 04:36:28 +0000 (Wed, 20 Jul 2022)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-28 16:45:44 +0000 (Thu, 28 Jul 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2441-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2441-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222441-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1193913");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-July/011595.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2-numpy' package(s) announced via the SUSE-SU-2022:2441-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python2-numpy fixes the following issues:

- CVE-2021-33430: Fixed buffer overflow that could lead to DoS in PyArray_NewFromDescr_int function of ctors.c (bsc#1193913).
- CVE-2021-41496: Fixed buffer overflow that could lead to DoS in array_from_pyobj function of fortranobject.c (bsc#1193907).
- CVE-2021-41495: Fixed Null Pointer Dereference in numpy.sort (bsc#1193911).");

  script_tag(name:"affected", value:"'python2-numpy' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server for SAP Applications 15, SUSE Linux Enterprise Server for SAP Applications 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"python2-numpy", rpm:"python2-numpy~1.16.5~150000.1.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-numpy-devel", rpm:"python2-numpy-devel~1.16.5~150000.1.9.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"python2-numpy", rpm:"python2-numpy~1.16.5~150000.1.9.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-numpy-devel", rpm:"python2-numpy-devel~1.16.5~150000.1.9.1", rls:"SLES15.0SP1"))) {
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
