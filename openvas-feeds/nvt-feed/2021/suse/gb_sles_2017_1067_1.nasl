# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2017.1067.1");
  script_cve_id("CVE-2014-4975", "CVE-2015-1855", "CVE-2015-3900", "CVE-2015-7551", "CVE-2016-2339");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-11 02:51:48 +0000 (Wed, 11 Jan 2017)");

  script_name("SUSE: Security Advisory (SUSE-SU-2017:1067-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP1|SLES12\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2017:1067-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2017/suse-su-20171067-1.html");
  script_xref(name:"URL", value:"http://svn.ruby-lang.org/repos/ruby/tags/v2_1_9/ChangeLog");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1014863");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1018808");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/887877");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/909695");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/926974");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/936032");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/959495");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/986630");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2017-April/002820.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.1' package(s) announced via the SUSE-SU-2017:1067-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This ruby2.1 update to version 2.1.9 fixes the following issues:

Security issues fixed:
- CVE-2016-2339: heap overflow vulnerability in the Fiddle::Function.new'initialize' (bsc#1018808)
- CVE-2015-7551: Unsafe tainted string usage in Fiddle and DL (bsc#959495)
- CVE-2015-3900: hostname validation does not work when fetching gems or making API requests (bsc#936032)
- CVE-2015-1855: Ruby'a OpenSSL extension suffers a vulnerability through overly permissive matching of
 hostnames (bsc#926974)
- CVE-2014-4975: off-by-one stack-based buffer overflow in the encodes() function (bsc#887877)

Bugfixes:
- SUSEconnect doesn't handle domain wildcards in no_proxy environment variable properly (bsc#1014863)
- Segmentation fault after pack & ioctl & unpack (bsc#909695)
- Ruby:HTTP Header injection in 'net/http' (bsc#986630)

ChangeLog:
- [link moved to references]");

  script_tag(name:"affected", value:"'ruby2.1' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Desktop 12-SP2, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server for Raspberry Pi 12-SP2, SUSE Linux Enterprise Server for SAP Applications 12-SP1, SUSE Linux Enterprise Server for SAP Applications 12-SP2.");

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

if(release == "SLES12.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libruby2_1-2_1", rpm:"libruby2_1-2_1~2.1.9~15.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1", rpm:"ruby2.1~2.1.9~15.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-stdlib", rpm:"ruby2.1-stdlib~2.1.9~15.1", rls:"SLES12.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"libruby2_1-2_1", rpm:"libruby2_1-2_1~2.1.9~15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1", rpm:"ruby2.1~2.1.9~15.1", rls:"SLES12.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.1-stdlib", rpm:"ruby2.1-stdlib~2.1.9~15.1", rls:"SLES12.0SP2"))) {
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
