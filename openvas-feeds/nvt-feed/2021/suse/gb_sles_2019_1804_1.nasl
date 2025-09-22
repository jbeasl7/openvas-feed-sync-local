# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2019.1804.1");
  script_cve_id("CVE-2017-17742", "CVE-2018-1000073", "CVE-2018-1000074", "CVE-2018-1000075", "CVE-2018-1000076", "CVE-2018-1000077", "CVE-2018-1000078", "CVE-2018-1000079", "CVE-2018-16395", "CVE-2018-16396", "CVE-2018-6914", "CVE-2018-8777", "CVE-2018-8778", "CVE-2018-8779", "CVE-2018-8780", "CVE-2019-8320", "CVE-2019-8321", "CVE-2019-8322", "CVE-2019-8323", "CVE-2019-8324", "CVE-2019-8325");
  script_tag(name:"creation_date", value:"2021-06-09 14:57:22 +0000 (Wed, 09 Jun 2021)");
  script_version("2024-02-02T14:37:50+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:50 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-07 14:13:18 +0000 (Fri, 07 Jun 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2019:1804-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2019:1804-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2019/suse-su-20191804-1/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2019/03/15/ruby-2-5-5-released/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2019/03/13/ruby-2-5-4-released/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.5, ruby-bundled-gems-rpmhelper' package(s) announced via the SUSE-SU-2019:1804-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for ruby2.5 and ruby-bundled-gems-rpmhelper fixes the following issues:

Changes in ruby2.5:

Update to 2.5.5 and 2.5.4:

[link moved to references]
[link moved to references]

Security issues fixed:
CVE-2019-8320: Delete directory using symlink when decompressing tar
 (bsc#1130627)

CVE-2019-8321: Escape sequence injection vulnerability in verbose
 (bsc#1130623)

CVE-2019-8322: Escape sequence injection vulnerability in gem
 owner (bsc#1130622)

CVE-2019-8323: Escape sequence injection vulnerability in API response
 handling (bsc#1130620)

CVE-2019-8324: Installing a malicious gem may lead to arbitrary code
 execution (bsc#1130617)

CVE-2019-8325: Escape sequence injection vulnerability in errors
 (bsc#1130611)


Ruby 2.5 was updated to 2.5.3:

This release includes some bug fixes and some security fixes.

Security issues fixed:
CVE-2018-16396: Tainted flags are not propagated in Array#pack and
 String#unpack with some directives (bsc#1112532)

CVE-2018-16395: OpenSSL::X509::Name equality check does not work
 correctly (bsc#1112530)

Ruby 2.5 was updated to 2.5.1:

This release includes some bug fixes and some security fixes.

Security issues fixed:
CVE-2017-17742: HTTP response splitting in WEBrick (bsc#1087434)

CVE-2018-6914: Unintentional file and directory creation with directory
 traversal in tempfile and tmpdir (bsc#1087441)

CVE-2018-8777: DoS by large request in WEBrick (bsc#1087436)

CVE-2018-8778: Buffer under-read in String#unpack (bsc#1087433)

CVE-2018-8779: Unintentional socket creation by poisoned NUL byte in
 UNIXServer and UNIXSocket (bsc#1087440)

CVE-2018-8780: Unintentional directory traversal by poisoned NUL byte in
 Dir (bsc#1087437)
Multiple vulnerabilities in RubyGems were fixed:

 - CVE-2018-1000079: Fixed path traversal issue during gem installation
 allows to write to arbitrary filesystem locations (bsc#1082058)
 - CVE-2018-1000075: Fixed infinite loop vulnerability due to negative
 size in tar header causes Denial of Service (bsc#1082014)
 - CVE-2018-1000078: Fixed XSS vulnerability in homepage attribute when
 displayed via gem server (bsc#1082011)
 - CVE-2018-1000077: Fixed that missing URL validation on spec home
 attribute allows malicious gem to set an invalid homepage URL
 (bsc#1082010)
 - CVE-2018-1000076: Fixed improper verification of signatures in tarball
 allows to install mis-signed gem (bsc#1082009)
 - CVE-2018-1000074: Fixed unsafe Object Deserialization Vulnerability in
 gem owner allowing arbitrary code execution on specially crafted YAML
 (bsc#1082008)
 - CVE-2018-1000073: Fixed path traversal when writing to a symlinked
 basedir outside of the root (bsc#1082007)

Other changes:
Fixed Net::POPMail methods modify frozen literal when using default arg

ruby: change over of the Japanese Era to the new emperor May 1st 2019
 ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'ruby2.5, ruby-bundled-gems-rpmhelper' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"libruby2_5-2_5", rpm:"libruby2_5-2_5~2.5.5~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2_5-2_5-debuginfo", rpm:"libruby2_5-2_5-debuginfo~2.5.5~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5", rpm:"ruby2.5~2.5.5~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-debuginfo", rpm:"ruby2.5-debuginfo~2.5.5~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-debugsource", rpm:"ruby2.5-debugsource~2.5.5~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel", rpm:"ruby2.5-devel~2.5.5~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel-extra", rpm:"ruby2.5-devel-extra~2.5.5~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-stdlib", rpm:"ruby2.5-stdlib~2.5.5~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-stdlib-debuginfo", rpm:"ruby2.5-stdlib-debuginfo~2.5.5~4.3.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"libruby2_5-2_5", rpm:"libruby2_5-2_5~2.5.5~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libruby2_5-2_5-debuginfo", rpm:"libruby2_5-2_5-debuginfo~2.5.5~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5", rpm:"ruby2.5~2.5.5~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-debuginfo", rpm:"ruby2.5-debuginfo~2.5.5~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-debugsource", rpm:"ruby2.5-debugsource~2.5.5~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel", rpm:"ruby2.5-devel~2.5.5~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-devel-extra", rpm:"ruby2.5-devel-extra~2.5.5~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-stdlib", rpm:"ruby2.5-stdlib~2.5.5~4.3.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby2.5-stdlib-debuginfo", rpm:"ruby2.5-stdlib-debuginfo~2.5.5~4.3.1", rls:"SLES15.0SP1"))) {
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
