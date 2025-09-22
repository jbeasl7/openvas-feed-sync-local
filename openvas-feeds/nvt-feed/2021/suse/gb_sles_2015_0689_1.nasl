# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2015.0689.1");
  script_cve_id("CVE-2003-1418", "CVE-2013-1862", "CVE-2013-1896", "CVE-2013-5704", "CVE-2013-6438", "CVE-2014-0098", "CVE-2014-0226", "CVE-2014-0231", "CVE-2014-3581");
  script_tag(name:"creation_date", value:"2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)");
  script_version("2025-08-15T15:42:24+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:24 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("SUSE: Security Advisory (SUSE-SU-2015:0689-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2015:0689-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2015/suse-su-20150689-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/713970");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/791794");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/815621");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/829056");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/829057");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/844212");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/852401");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/859916");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/869105");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/869106");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/871310");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/887765");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/887768");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/894225");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/899836");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/904427");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907339");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/907477");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2015-April/001337.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache2' package(s) announced via the SUSE-SU-2015:0689-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for the Apache Web Server introduces directives to control two
protocol options:

 * HttpContentLengthHeadZero: Allow responses to HEAD request with
 Content-Length of 0
 * HttpExpectStrict: Allow the administrator to control whether clients
 must send '100-continue'

MODULE_MAGIC_NUMBER_MINOR has been increased to 24, as this change is not
forward-compatible. Modules built against this release might not work
correctly with older releases of the Apache Web Server.");

  script_tag(name:"affected", value:"'apache2' package(s) on SUSE Linux Enterprise Server 11-SP3, SUSE Linux Enterprise Server for SAP Applications 11-SP3.");

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

  if(!isnull(res = isrpmvuln(pkg:"apache2", rpm:"apache2~2.2.12~1.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-doc", rpm:"apache2-doc~2.2.12~1.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-example-pages", rpm:"apache2-example-pages~2.2.12~1.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-prefork", rpm:"apache2-prefork~2.2.12~1.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-utils", rpm:"apache2-utils~2.2.12~1.50.1", rls:"SLES11.0SP3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-worker", rpm:"apache2-worker~2.2.12~1.50.1", rls:"SLES11.0SP3"))) {
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
