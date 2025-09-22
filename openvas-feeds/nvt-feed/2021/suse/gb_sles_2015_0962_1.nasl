# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0962.1");
  script_cve_id("CVE-2013-2174", "CVE-2013-4545", "CVE-2014-0015", "CVE-2014-0138", "CVE-2014-0139", "CVE-2015-3143", "CVE-2015-3148", "CVE-2015-3153");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0962-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0962-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150962-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/824517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/849596");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/858673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/868627");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/868629");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870444");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927174");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/928533");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-May/001414.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the SUSE-SU-2015:0962-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This curl update fixes the following security issues:

 * bnc#868627: wrong re-use of connections (CVE-2014-0138).
 * bnc#868629: IP address wildcard certificate validation
 (CVE-2014-0139).
 * bnc#870444: --insecure option inappropriately enforcing security
 safeguard.

Security Issue references:

 * CVE-2014-0138
 <[link moved to references]>
 * CVE-2014-0139
 <[link moved to references]>");

  script_tag(name:"affected", value:"'curl' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

if(release == "SLES11.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.19.7~1.38.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-32bit", rpm:"libcurl4-32bit~7.19.7~1.38.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.19.7~1.38.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4-x86", rpm:"libcurl4-x86~7.19.7~1.38.1", rls:"SLES11.0SP3"))) {
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
