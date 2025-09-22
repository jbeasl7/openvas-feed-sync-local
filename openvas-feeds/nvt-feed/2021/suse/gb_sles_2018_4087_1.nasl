# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2018.4087.1");
  script_cve_id("CVE-2018-17183", "CVE-2018-17961", "CVE-2018-18073", "CVE-2018-18284", "CVE-2018-19409", "CVE-2018-19475", "CVE-2018-19476", "CVE-2018-19477");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:32 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-18 14:19:15 +0000 (Tue, 18 Dec 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2018:4087-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2018:4087-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2018/suse-su-20184087-1/");
  script_xref(name:"URL", value:"http://www.ghostscript.com/doc/9.26/News.htm");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghostscript' package(s) announced via the SUSE-SU-2018:4087-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ghostscript to version 9.26 fixes the following issues:

Security issues fixed:
CVE-2018-19475: Fixed bypass of an intended access restriction in
 psi/zdevice2.c (bsc#1117327)

CVE-2018-19476: Fixed bypass of an intended access restriction in
 psi/zicc.c (bsc#1117313)

CVE-2018-19477: Fixed bypass of an intended access restriction in
 psi/zfjbig2.c (bsc#1117274)

CVE-2018-19409: Check if another device is used correctly in
 LockSafetyParams (bsc#1117022)

CVE-2018-18284: Fixed potential sandbox escape through 1Policy operator
 (bsc#1112229)

CVE-2018-18073: Fixed leaks through operator in saved execution stacks
 (bsc#1111480)

CVE-2018-17961: Fixed a -dSAFER sandbox escape by bypassing executeonly
 (bsc#1111479)

CVE-2018-17183: Fixed a potential code injection by specially crafted
 PostScript files (bsc#1109105)

Version update to 9.26 (bsc#1117331):
Security issues have been the primary focus

Minor bug fixes and improvements

For release summary see: [link moved to references]");

  script_tag(name:"affected", value:"'ghostscript' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Desktop Applications 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15.");

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

  if(!isnull(res = isrpmvuln(pkg:"ghostscript", rpm:"ghostscript~9.26~3.9.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debuginfo", rpm:"ghostscript-debuginfo~9.26~3.9.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-debugsource", rpm:"ghostscript-debugsource~9.26~3.9.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-devel", rpm:"ghostscript-devel~9.26~3.9.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-x11", rpm:"ghostscript-x11~9.26~3.9.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ghostscript-x11-debuginfo", rpm:"ghostscript-x11-debuginfo~9.26~3.9.4", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspectre-debugsource", rpm:"libspectre-debugsource~0.2.8~3.4.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspectre-devel", rpm:"libspectre-devel~0.2.8~3.4.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspectre1", rpm:"libspectre1~0.2.8~3.4.3", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libspectre1-debuginfo", rpm:"libspectre1-debuginfo~0.2.8~3.4.3", rls:"SLES15.0"))) {
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
