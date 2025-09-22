# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.3367.1");
  script_cve_id("CVE-2019-18900");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-06 17:08:19 +0000 (Thu, 06 Feb 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:3367-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:3367-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20203367-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1158763");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1169947");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1178038");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-November/007791.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libzypp, zypper' package(s) announced via the SUSE-SU-2020:3367-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libzypp, zypper fixes the following issues:

libzypp fixes the following security issue:

- CVE-2019-18900: Fixed assert cookie file that was world readable (bsc#1158763).

zypper was updated to fix the following issues:

- Fixed an issue, where zypper crashed when the system language is set to Spanish and the user
 tried to patch their system with 'zypper patch --category security' (bsc#1178038)
- Fixed a typo in man page (bsc#1169947)");

  script_tag(name:"affected", value:"'libzypp, zypper' package(s) on SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"libzypp", rpm:"libzypp~16.21.2~27.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libzypp-devel", rpm:"libzypp-devel~16.21.2~27.70.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper", rpm:"zypper~1.13.57~18.46.3", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zypper-log", rpm:"zypper-log~1.13.57~18.46.3", rls:"SLES12.0SP2"))) {
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
