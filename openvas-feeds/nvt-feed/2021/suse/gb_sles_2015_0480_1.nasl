# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0480.1");
  script_cve_id("CVE-2011-1910", "CVE-2011-2464", "CVE-2011-4313", "CVE-2012-1667", "CVE-2012-3817", "CVE-2012-4244", "CVE-2012-5166", "CVE-2014-0591", "CVE-2014-8500");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0480-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0480-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150480-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/684163");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/696585");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/703907");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/715180");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/718441");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/727495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/730995");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/743758");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/765315");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/772945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/780157");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/784602");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/796112");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/858639");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/908994");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-March/001281.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2015:0480-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes a DoS vulnerability in bind when handling malformed
NSEC3-signed zones. CVE-2014-0591 has been assigned to this issue.

Security Issue references:

 * CVE-2014-0591
 <[link moved to references]>");

  script_tag(name:"affected", value:"'bind' package(s) on SUSE Linux Enterprise Server 11-SP1.");

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

if(release == "SLES11.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.6ESVR10P2~0.6.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.6ESVR10P2~0.6.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.6ESVR10P2~0.6.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs-32bit", rpm:"bind-libs-32bit~9.6ESVR10P2~0.6.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-libs", rpm:"bind-libs~9.6ESVR10P2~0.6.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.6ESVR10P2~0.6.1", rls:"SLES11.0SP1"))) {
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
