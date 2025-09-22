# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0439.1");
  script_cve_id("CVE-2012-4412", "CVE-2012-6656", "CVE-2013-0242", "CVE-2013-1914", "CVE-2013-4237", "CVE-2013-4332", "CVE-2013-4357", "CVE-2013-4458", "CVE-2013-4788", "CVE-2013-7423", "CVE-2014-0475", "CVE-2014-4043", "CVE-2014-5119", "CVE-2014-6040", "CVE-2014-7817", "CVE-2014-9402", "CVE-2015-0235", "CVE-2015-1472");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-14 16:31:28 +0000 (Tue, 14 Jan 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0439-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0439-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150439-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/691365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/779320");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/791928");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/801246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/811979");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/813121");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/819347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/822210");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/827811");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828235");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/828637");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/830268");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/834594");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/836746");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/839870");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/844309");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/847227");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/854445");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/863499");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/864081");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/872832");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/882028");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/882600");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/883217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/886416");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/887022");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/888347");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/891843");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/892065");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/892073");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/894553");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/894556");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903288");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904461");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/906371");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909053");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/913646");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/915526");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/916222");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/917072");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/919678");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-March/001271.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc' package(s) announced via the SUSE-SU-2015:0439-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This glibc update fixes a critical privilege escalation problem and two
non-security issues:

 * bnc#892073: An off-by-one error leading to a heap-based buffer
 overflow was found in __gconv_translit_find(). An exploit that
 targets the problem is publicly available. (CVE-2014-5119)
 * bnc#892065: setenv-alloca.patch: Avoid unbound alloca in setenv.
 * bnc#888347: printf-multibyte-format.patch: Don't parse %s format
 argument as multi-byte string.

Security Issues:

 * CVE-2014-5119
 <[link moved to references]>");

  script_tag(name:"affected", value:"'glibc' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.11.3~17.72.14", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-32bit", rpm:"glibc-32bit~2.11.3~17.72.14", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.11.3~17.72.14", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-devel-32bit", rpm:"glibc-devel-32bit~2.11.3~17.72.14", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-html", rpm:"glibc-html~2.11.3~17.72.14", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-i18ndata", rpm:"glibc-i18ndata~2.11.3~17.72.14", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-info", rpm:"glibc-info~2.11.3~17.72.14", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale", rpm:"glibc-locale~2.11.3~17.72.14", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-32bit", rpm:"glibc-locale-32bit~2.11.3~17.72.14", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-locale-x86", rpm:"glibc-locale-x86~2.11.3~17.72.14", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile", rpm:"glibc-profile~2.11.3~17.72.14", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile-32bit", rpm:"glibc-profile-32bit~2.11.3~17.72.14", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-profile-x86", rpm:"glibc-profile-x86~2.11.3~17.72.14", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"glibc-x86", rpm:"glibc-x86~2.11.3~17.72.14", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.11.3~17.72.14", rls:"SLES11.0SP3"))) {
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
