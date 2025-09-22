# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3117.1");
  script_cve_id("CVE-2019-5068");
  script_tag(name:"creation_date", value:"2021-09-23 07:04:43 +0000 (Thu, 23 Sep 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"3.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-12 20:32:51 +0000 (Tue, 12 Nov 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3117-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3117-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213117-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156015");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-September/009451.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Mesa' package(s) announced via the SUSE-SU-2021:3117-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for Mesa fixes the following issues:

Security issue fixed:

- CVE-2019-5068: Fixed exploitable shared memory permissions vulnerability (bsc#1156015).");

  script_tag(name:"affected", value:"'Mesa' package(s) on SUSE Linux Enterprise Server 12-SP2.");

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

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"Mesa", rpm:"Mesa~11.2.1~104.9.49", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-32bit", rpm:"Mesa-32bit~11.2.1~104.9.49", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1", rpm:"Mesa-libEGL1~11.2.1~104.9.49", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libEGL1-32bit", rpm:"Mesa-libEGL1-32bit~11.2.1~104.9.49", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1", rpm:"Mesa-libGL1~11.2.1~104.9.49", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGL1-32bit", rpm:"Mesa-libGL1-32bit~11.2.1~104.9.49", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libGLESv2-2", rpm:"Mesa-libGLESv2-2~11.2.1~104.9.49", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0", rpm:"Mesa-libglapi0~11.2.1~104.9.49", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"Mesa-libglapi0-32bit", rpm:"Mesa-libglapi0-32bit~11.2.1~104.9.49", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1", rpm:"libgbm1~11.2.1~104.9.49", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgbm1-32bit", rpm:"libgbm1-32bit~11.2.1~104.9.49", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxatracker2", rpm:"libxatracker2~1.0.0~104.9.49", rls:"SLES12.0SP2"))) {
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
