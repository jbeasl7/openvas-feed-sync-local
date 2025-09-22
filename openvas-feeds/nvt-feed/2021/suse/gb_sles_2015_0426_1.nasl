# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0426.1");
  script_cve_id("CVE-2013-2486", "CVE-2013-2487", "CVE-2013-3555", "CVE-2013-3556", "CVE-2013-3557", "CVE-2013-3558", "CVE-2013-3559", "CVE-2013-3560", "CVE-2013-3561", "CVE-2013-3562", "CVE-2013-4074", "CVE-2013-4075", "CVE-2013-4076", "CVE-2013-4077", "CVE-2013-4078", "CVE-2013-4079", "CVE-2013-4080", "CVE-2013-4081", "CVE-2013-4082", "CVE-2013-4083", "CVE-2013-4929", "CVE-2013-4930", "CVE-2013-4931", "CVE-2013-4932", "CVE-2013-4933", "CVE-2013-4934", "CVE-2013-4935", "CVE-2013-6336", "CVE-2013-6337", "CVE-2013-6338", "CVE-2013-6339", "CVE-2013-6340", "CVE-2013-7112", "CVE-2013-7113", "CVE-2013-7114", "CVE-2014-2281", "CVE-2014-2282", "CVE-2014-2283", "CVE-2014-2299", "CVE-2014-6421", "CVE-2014-6422", "CVE-2014-6423", "CVE-2014-6424", "CVE-2014-6427", "CVE-2014-6428", "CVE-2014-6429", "CVE-2014-6430", "CVE-2014-6431", "CVE-2014-6432", "CVE-2014-8710", "CVE-2014-8711", "CVE-2014-8712", "CVE-2014-8713", "CVE-2014-8714", "CVE-2015-0559", "CVE-2015-0560", "CVE-2015-0561", "CVE-2015-0562", "CVE-2015-0563", "CVE-2015-0564", "CVE-2015-2188", "CVE-2015-2189", "CVE-2015-2191", "CVE-2015-3811", "CVE-2015-3812", "CVE-2015-3814");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0426-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0426-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150426-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/813217");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/816517");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/816887");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/820973");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/824900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/831718");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/839607");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/848738");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/855980");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/856495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/856496");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/856498");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/867485");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/889854");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/889899");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/889900");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/889901");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/889906");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/897055");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/899303");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905245");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905246");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905247");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/905248");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912365");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912370");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/912372");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920696");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920697");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/920699");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/930691");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-March/001267.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/docs/relnotes/wireshark-1.10.11.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2015:0426-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"wireshark has been updated to version 1.10.11 to fix five security issues.

These security issues have been fixed:

 * SigComp UDVM buffer overflow (CVE-2014-8710).
 * AMQP dissector crash (CVE-2014-8711).
 * NCP dissector crashes (CVE-2014-8712, CVE-2014-8713).
 * TN5250 infinite loops (CVE-2014-8714).

This non-security issue has been fixed:

 * enable zlib (bnc#899303).

Further bug fixes and updated protocol support as listed in:

[link moved to references]
<[link moved to references]>

Security Issues:

 * CVE-2014-8711
 <[link moved to references]>
 * CVE-2014-8710
 <[link moved to references]>
 * CVE-2014-8714
 <[link moved to references]>
 * CVE-2014-8712
 <[link moved to references]>
 * CVE-2014-8713
 <[link moved to references]>");

  script_tag(name:"affected", value:"'wireshark' package(s) on SUSE Linux Enterprise Desktop 11-SP3, SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.10.11~0.2.1", rls:"SLES11.0SP3"))) {
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
