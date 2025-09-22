# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0940.1");
  script_cve_id("CVE-2012-5510", "CVE-2012-5511", "CVE-2012-5513", "CVE-2012-5514", "CVE-2012-5515", "CVE-2013-3495", "CVE-2014-4021", "CVE-2014-7154", "CVE-2014-7155", "CVE-2014-7156", "CVE-2014-8594", "CVE-2014-8595", "CVE-2014-8866", "CVE-2014-8867", "CVE-2014-9030", "CVE-2015-3340", "CVE-2015-3456");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:12 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0940-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0940-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150940-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/777628");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789944");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789945");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789948");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789950");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/789951");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/826717");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/880751");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/895798");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/895799");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/895802");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903850");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/903970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905465");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905467");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/906439");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/927967");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/929339");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-May/001404.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Xen' package(s) announced via the SUSE-SU-2015:0940-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following security issues in Xen:

 * CVE-2012-5510: Grant table version switch list corruption
 vulnerability (XSA-26)
 * CVE-2012-5511: Several HVM operations do not validate the range of
 their inputs (XSA-27)
 * CVE-2012-5513: XENMEM_exchange may overwrite hypervisor memory
 (XSA-29)
 * CVE-2012-5514: Missing unlock in
 guest_physmap_mark_populate_on_demand() (XSA-30)
 * CVE-2012-5515: Several memory hypercall operations allow invalid
 extent order values (XSA-31)

Also the following fix has been applied:

 * bnc#777628 - guest 'disappears' after live migration
 Updated block-dmmd script

Security Issues references:

 * CVE-2012-5513
 <[link moved to references]>
 * CVE-2012-5514
 <[link moved to references]>
 * CVE-2012-5511
 <[link moved to references]>
 * CVE-2012-5510
 <[link moved to references]>
 * CVE-2012-5515
 <[link moved to references]>");

  script_tag(name:"affected", value:"'Xen' package(s) on SUSE Linux Enterprise Server 11-SP1.");

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

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.0.3_21548_12~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.0.3_21548_12~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.0.3_21548_12~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.0.3_21548_12_2.6.32.54_0.11.TDC~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.0.3_21548_18_2.6.32.59_0.19~0.21.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-trace", rpm:"xen-kmp-trace~4.0.3_21548_12_2.6.32.54_0.11.TDC~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.0.3_21548_12~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.0.3_21548_12~0.3.1", rls:"SLES11.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.0.3_21548_12~0.3.1", rls:"SLES11.0SP1"))) {
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
