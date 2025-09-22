# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852995");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-1088", "CVE-2018-10904", "CVE-2018-10907", "CVE-2018-10911", "CVE-2018-10913", "CVE-2018-10914", "CVE-2018-10923", "CVE-2018-10924", "CVE-2018-10926", "CVE-2018-10927", "CVE-2018-10928", "CVE-2018-10929", "CVE-2018-10930", "CVE-2018-1112");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:38:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2020-01-27 09:17:28 +0000 (Mon, 27 Jan 2020)");
  script_name("openSUSE: Security Advisory for glusterfs (openSUSE-SU-2020:0079_1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0079-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2020-01/msg00035.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glusterfs'
  package(s) announced via the openSUSE-SU-2020:0079-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for glusterfs fixes the following issues:

  glusterfs was update to release 3.12.15:

  * Fixed a number of bugs and security issues:

  - CVE-2018-1088, CVE-2018-1112 [boo#1090084], CVE-2018-10904
  [boo#1107018], CVE-2018-10907 [boo#1107019], CVE-2018-10911
  [boo#1107020], CVE-2018-10913 [boo#1107021], CVE-2018-10914
  [boo#1107022], CVE-2018-10923 [boo#1107023], CVE-2018-10924
  [boo#1107024], CVE-2018-10926 [boo#1107025], CVE-2018-10927
  [boo#1107026], CVE-2018-10928 [boo#1107027], CVE-2018-10928
  [boo#1107027], CVE-2018-10929 [boo#1107028], CVE-2018-10930
  [boo#1107029], boo#1105776.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-79=1");

  script_tag(name:"affected", value:"'glusterfs' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"glusterfs", rpm:"glusterfs~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-debuginfo", rpm:"glusterfs-debuginfo~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-debugsource", rpm:"glusterfs-debugsource~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glusterfs-devel", rpm:"glusterfs-devel~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfapi0", rpm:"libgfapi0~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfapi0-debuginfo", rpm:"libgfapi0-debuginfo~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfchangelog0", rpm:"libgfchangelog0~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfchangelog0-debuginfo", rpm:"libgfchangelog0-debuginfo~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfdb0", rpm:"libgfdb0~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfdb0-debuginfo", rpm:"libgfdb0-debuginfo~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfrpc0", rpm:"libgfrpc0~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfrpc0-debuginfo", rpm:"libgfrpc0-debuginfo~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfxdr0", rpm:"libgfxdr0~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgfxdr0-debuginfo", rpm:"libgfxdr0-debuginfo~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglusterfs0", rpm:"libglusterfs0~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libglusterfs0-debuginfo", rpm:"libglusterfs0-debuginfo~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-gluster", rpm:"python-gluster~3.12.15~lp151.3.3.1", rls:"openSUSELeap15.1"))) {
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
