# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.1184.1");
  script_cve_id("CVE-2006-7250", "CVE-2009-5146", "CVE-2010-2939", "CVE-2010-3864", "CVE-2010-4180", "CVE-2011-0014", "CVE-2011-1945", "CVE-2011-3210", "CVE-2011-4108", "CVE-2011-4109", "CVE-2011-4576", "CVE-2011-4577", "CVE-2011-4619", "CVE-2011-5095", "CVE-2012-0050", "CVE-2012-0884", "CVE-2012-1165", "CVE-2012-2110", "CVE-2012-2333", "CVE-2013-0166", "CVE-2013-0169", "CVE-2014-0076", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470", "CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3508", "CVE-2014-3510", "CVE-2014-3513", "CVE-2014-3566", "CVE-2014-3567", "CVE-2014-3568", "CVE-2014-3570", "CVE-2014-3571", "CVE-2014-3572", "CVE-2014-8275", "CVE-2015-0204", "CVE-2015-0205", "CVE-2015-0209", "CVE-2015-0286", "CVE-2015-0287", "CVE-2015-0288", "CVE-2015-0289", "CVE-2015-0292", "CVE-2015-0293", "CVE-2015-1788", "CVE-2015-1789", "CVE-2015-1790", "CVE-2015-1791", "CVE-2015-1792", "CVE-2015-3216", "CVE-2015-4000");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2015-06-15 15:14:35 +0000 (Mon, 15 Jun 2015)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:1184-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:1184-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20151184-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/608666");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/629905");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/651003");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/657663");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/670526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/693027");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/716144");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/739719");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/742821");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/743344");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/748738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/749210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/749213");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/749735");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/751946");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/751977");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/755395");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/758060");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/761324");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/761838");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/767256");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/768097");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/779952");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/802648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/802746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/859228");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/859924");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/860332");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/862181");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/869945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/870192");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/879179");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880891");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/890764");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/890767");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/890768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/890769");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/890770");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/892403");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/901223");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/901277");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912014");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912015");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912018");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912293");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912294");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912296");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915976");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919648");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920236");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922488");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922500");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/922501");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929678");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/931698");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933898");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/933911");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934487");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934489");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934491");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/934493");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-July/001477.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'OpenSSL' package(s) announced via the SUSE-SU-2015:1184-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This OpenSSL update fixes the following issues:

 * Session Ticket Memory Leak (CVE-2014-3567)
 * Build option no-ssl3 is incomplete (CVE-2014-3568)
 * Add support for TLS_FALLBACK_SCSV to mitigate CVE-2014-3566 (POODLE)

Security Issues:

 * CVE-2014-3567
 <[link moved to references]>
 * CVE-2014-3566
 <[link moved to references]>
 * CVE-2014-3568
 <[link moved to references]>");

  script_tag(name:"affected", value:"'OpenSSL' package(s) on SUSE Linux Enterprise Server 11-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"libopenssl-devel", rpm:"libopenssl-devel~0.9.8j~0.66.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8", rpm:"libopenssl0_9_8~0.9.8j~0.66.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-32bit", rpm:"libopenssl0_9_8-32bit~0.9.8j~0.66.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-hmac", rpm:"libopenssl0_9_8-hmac~0.9.8j~0.66.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libopenssl0_9_8-hmac-32bit", rpm:"libopenssl0_9_8-hmac-32bit~0.9.8j~0.66.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl", rpm:"openssl~0.9.8j~0.66.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openssl-doc", rpm:"openssl-doc~0.9.8j~0.66.1", rls:"SLES11.0SP1"))) {
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
