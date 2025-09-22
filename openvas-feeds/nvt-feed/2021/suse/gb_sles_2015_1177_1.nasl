# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1177.1");
  script_cve_id("CVE-2012-5615", "CVE-2013-1861", "CVE-2013-3783", "CVE-2013-3793", "CVE-2013-3794", "CVE-2013-3795", "CVE-2013-3796", "CVE-2013-3798", "CVE-2013-3801", "CVE-2013-3802", "CVE-2013-3804", "CVE-2013-3805", "CVE-2013-3806", "CVE-2013-3807", "CVE-2013-3808", "CVE-2013-3809", "CVE-2013-3810", "CVE-2013-3811", "CVE-2013-3812", "CVE-2013-4316", "CVE-2013-5860", "CVE-2013-5881", "CVE-2013-5882", "CVE-2013-5891", "CVE-2013-5894", "CVE-2013-5908", "CVE-2014-0001", "CVE-2014-0224", "CVE-2014-0384", "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0401", "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0420", "CVE-2014-0427", "CVE-2014-0430", "CVE-2014-0431", "CVE-2014-0433", "CVE-2014-0437", "CVE-2014-2419", "CVE-2014-2430", "CVE-2014-2431", "CVE-2014-2432", "CVE-2014-2434", "CVE-2014-2435", "CVE-2014-2436", "CVE-2014-2438", "CVE-2014-2440", "CVE-2014-2442", "CVE-2014-2444", "CVE-2014-2450", "CVE-2014-2451", "CVE-2014-2484", "CVE-2014-2494", "CVE-2014-3569", "CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-4207", "CVE-2014-4214", "CVE-2014-4233", "CVE-2014-4238", "CVE-2014-4240", "CVE-2014-4243", "CVE-2014-4258", "CVE-2014-4260", "CVE-2014-4274", "CVE-2014-4287", "CVE-2014-6463", "CVE-2014-6464", "CVE-2014-6469", "CVE-2014-6474", "CVE-2014-6478", "CVE-2014-6484", "CVE-2014-6489", "CVE-2014-6491", "CVE-2014-6494", "CVE-2014-6495", "CVE-2014-6496", "CVE-2014-6500", "CVE-2014-6505", "CVE-2014-6507", "CVE-2014-6520", "CVE-2014-6530", "CVE-2014-6551", "CVE-2014-6555", "CVE-2014-6559", "CVE-2014-6564", "CVE-2014-6568", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0206", "CVE-2015-0374", "CVE-2015-0381", "CVE-2015-0382", "CVE-2015-0385", "CVE-2015-0391", "CVE-2015-0405", "CVE-2015-0409", "CVE-2015-0411", "CVE-2015-0423", "CVE-2015-0432", "CVE-2015-0433", "CVE-2015-0438", "CVE-2015-0439", "CVE-2015-0441", "CVE-2015-0498", "CVE-2015-0499", "CVE-2015-0500", "CVE-2015-0501", "CVE-2015-0503", "CVE-2015-0505", "CVE-2015-0506", "CVE-2015-0507", "CVE-2015-0508", "CVE-2015-0511", "CVE-2015-2305", "CVE-2015-2566", "CVE-2015-2567", "CVE-2015-2568", "CVE-2015-2571", "CVE-2015-2573", "CVE-2015-2576", "CVE-2015-4000");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-06-06 14:29:47 +0000 (Fri, 06 Jun 2014)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1177-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1177-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151177-1.html");
  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/734436");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/768832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/780019");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789263");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/791863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/792332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/803040");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/830086");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/834028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/834967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/837801");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/857678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/858823");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/861493");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/868673");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/873896");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/878779");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/887580");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/901237");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/914058");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922043");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927623");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934789");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-July/001472.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MySQL' package(s) announced via the SUSE-SU-2015:1177-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This MySQL update provides the following:

 * upgrade to version 5.5.39, [bnc#887580]
 * CVE's fixed: CVE-2014-2484, CVE-2014-4258, CVE-2014-4260,
 CVE-2014-2494, CVE-2014-4238, CVE-2014-4207, CVE-2014-4233,
 CVE-2014-4240, CVE-2014-4214, CVE-2014-4243

See also:
[link moved to references]
<[link moved to references]>

Security Issues:

 * CVE-2014-2484
 <[link moved to references]>
 * CVE-2014-4258
 <[link moved to references]>
 * CVE-2014-4260
 <[link moved to references]>
 * CVE-2014-2494
 <[link moved to references]>
 * CVE-2014-4238
 <[link moved to references]>
 * CVE-2014-4207
 <[link moved to references]>
 * CVE-2014-4233
 <[link moved to references]>
 * CVE-2014-4240
 <[link moved to references]>
 * CVE-2014-4214
 <[link moved to references]>
 * CVE-2014-4243
 <[link moved to references]>");

  script_tag(name:"affected", value:"'MySQL' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-32bit", rpm:"libmysql55client18-32bit~5.5.39~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18", rpm:"libmysql55client18~5.5.39~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client18-x86", rpm:"libmysql55client18-x86~5.5.39~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysql55client_r18", rpm:"libmysql55client_r18~5.5.39~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15-32bit", rpm:"libmysqlclient15-32bit~5.0.96~0.6.13", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15", rpm:"libmysqlclient15~5.0.96~0.6.13", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient15-x86", rpm:"libmysqlclient15-x86~5.0.96~0.6.13", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libmysqlclient_r15", rpm:"libmysqlclient_r15~5.0.96~0.6.13", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql", rpm:"mysql~5.5.39~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-client", rpm:"mysql-client~5.5.39~0.7.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mysql-tools", rpm:"mysql-tools~5.5.39~0.7.1", rls:"SLES11.0SP3"))) {
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
