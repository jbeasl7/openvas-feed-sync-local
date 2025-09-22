# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1041.1");
  script_cve_id("CVE-2017-5837", "CVE-2017-5839", "CVE-2017-5842", "CVE-2017-5844");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-13 22:23:18 +0000 (Mon, 13 Feb 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1041-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1041-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171041-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024041");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024047");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024076");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1024079");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-April/002807.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-plugins-base' package(s) announced via the SUSE-SU-2017:1041-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-plugins-base fixes the following security issues:

- A crafted AVI file could have caused a floating point exception leading to
 DoS (bsc#1024076, CVE-2017-5837, bsc#1024079, CVE-2017-5844)
- A crafted AVI file could have caused a stack overflow leading to DoS
 (bsc#1024047, CVE-2017-5839)
- A crafted SAMI subtitle file could have caused an invalid memory access
 possibly leading to DoS or corruption (bsc#1024041, CVE-2017-5842)");

  script_tag(name:"affected", value:"'gstreamer-plugins-base' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base", rpm:"gstreamer-plugins-base~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-plugins-base-lang", rpm:"gstreamer-plugins-base-lang~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstallocators-1_0-0", rpm:"libgstallocators-1_0-0~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0", rpm:"libgstapp-1_0-0~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstapp-1_0-0-32bit", rpm:"libgstapp-1_0-0-32bit~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0", rpm:"libgstaudio-1_0-0~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstaudio-1_0-0-32bit", rpm:"libgstaudio-1_0-0-32bit~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstfft-1_0-0", rpm:"libgstfft-1_0-0~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0", rpm:"libgstpbutils-1_0-0~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstpbutils-1_0-0-32bit", rpm:"libgstpbutils-1_0-0-32bit~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstriff-1_0-0", rpm:"libgstriff-1_0-0~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtp-1_0-0", rpm:"libgstrtp-1_0-0~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstrtsp-1_0-0", rpm:"libgstrtsp-1_0-0~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstsdp-1_0-0", rpm:"libgstsdp-1_0-0~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0", rpm:"libgsttag-1_0-0~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgsttag-1_0-0-32bit", rpm:"libgsttag-1_0-0-32bit~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0", rpm:"libgstvideo-1_0-0~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstvideo-1_0-0-32bit", rpm:"libgstvideo-1_0-0-32bit~1.2.4~2.6.8", rls:"SLES12.0SP1"))) {
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
