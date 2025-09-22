# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2020.2914.1");
  script_cve_id("CVE-2017-3136", "CVE-2018-5741", "CVE-2019-6477", "CVE-2020-8616", "CVE-2020-8617", "CVE-2020-8618", "CVE-2020-8619", "CVE-2020-8620", "CVE-2020-8621", "CVE-2020-8622", "CVE-2020-8623", "CVE-2020-8624");
  script_tag(name:"creation_date", value:"2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)");
  script_version("2025-08-15T15:42:25+0000");
  script_tag(name:"last_modification", value:"2025-08-15 15:42:25 +0000 (Fri, 15 Aug 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-26 17:22:18 +0000 (Wed, 26 Aug 2020)");

  script_name("SUSE: Security Advisory (SUSE-SU-2020:2914-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP1|SLES15\.0SP2|SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2020:2914-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2020/suse-su-20202914-1.html");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1100369");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1109160");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118367");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1118368");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1128220");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1156205");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1157051");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1161168");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170667");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1170713");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171313");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1171740");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1172958");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173307");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173311");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1173983");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1175443");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176092");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/1176674");
  script_xref(name:"URL", value:"https://bugzilla.suse.com/906079");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2020-October/007552.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind' package(s) announced via the SUSE-SU-2020:2914-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:

BIND was upgraded to version 9.16.6:

Note:

- bind is now more strict in regards to DNSSEC. If queries are not working,
 check for DNSSEC issues. For instance, if bind is used in a namserver
 forwarder chain, the forwarding DNS servers must support DNSSEC.

Fixing security issues:

- CVE-2020-8616: Further limit the number of queries that can be triggered from
 a request. Root and TLD servers are no longer exempt
 from max-recursion-queries. Fetches for missing name server. (bsc#1171740)
 Address records are limited to 4 for any domain.
- CVE-2020-8617: Replaying a TSIG BADTIME response as a request could trigger an
 assertion failure. (bsc#1171740)
- CVE-2019-6477: Fixed an issue where TCP-pipelined queries could bypass
 the tcp-clients limit (bsc#1157051).
- CVE-2018-5741: Fixed the documentation (bsc#1109160).
- CVE-2020-8618: It was possible to trigger an INSIST when determining
 whether a record would fit into a TCP message buffer (bsc#1172958).
- CVE-2020-8619: It was possible to trigger an INSIST in
 lib/dns/rbtdb.c:new_reference() with a particular zone content
 and query patterns (bsc#1172958).
- CVE-2020-8624: 'update-policy' rules of type 'subdomain' were
 incorrectly treated as 'zonesub' rules, which allowed
 keys used in 'subdomain' rules to update names outside
 of the specified subdomains. The problem was fixed by
 making sure 'subdomain' rules are again processed as
 described in the ARM (bsc#1175443).
- CVE-2020-8623: When BIND 9 was compiled with native PKCS#11 support, it
 was possible to trigger an assertion failure in code
 determining the number of bits in the PKCS#11 RSA public
 key with a specially crafted packet (bsc#1175443).
- CVE-2020-8621: named could crash in certain query resolution scenarios
 where QNAME minimization and forwarding were both
 enabled (bsc#1175443).
- CVE-2020-8620: It was possible to trigger an assertion failure by
 sending a specially crafted large TCP DNS message (bsc#1175443).
- CVE-2020-8622: It was possible to trigger an assertion failure when
 verifying the response to a TSIG-signed request (bsc#1175443).

Other issues fixed:

- Add engine support to OpenSSL EdDSA implementation.
- Add engine support to OpenSSL ECDSA implementation.
- Update PKCS#11 EdDSA implementation to PKCS#11 v3.0.
- Warn about AXFR streams with inconsistent message IDs.
- Make ISC rwlock implementation the default again.
- Fixed issues when using cookie-secrets for AES and SHA2 (bsc#1161168)
- Installed the default files in /var/lib/named and created
 chroot environment on systems using transactional-updates (bsc#1100369, fate#325524)
- Fixed an issue where bind was not working in FIPS mode (bsc#906079).
- Fixed dependency issues (bsc#1118367 and bsc#1118368).
- GeoIP support is now discontinued, now GeoIP2 is used(bsc#1156205).
- Fixed an issue with FIPS (bsc#1128220).
- The liblwres library ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'bind' package(s) on SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP Applications 15.");

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

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600", rpm:"libbind9-1600~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600-debuginfo", rpm:"libbind9-1600-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605", rpm:"libdns1605~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605-debuginfo", rpm:"libdns1605-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs-devel", rpm:"libirs-devel~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601", rpm:"libirs1601~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601-debuginfo", rpm:"libirs1601-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606", rpm:"libisc1606~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606-debuginfo", rpm:"libisc1606-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600", rpm:"libisccc1600~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600-debuginfo", rpm:"libisccc1600-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600", rpm:"libisccfg1600~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600-debuginfo", rpm:"libisccfg1600-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604", rpm:"libns1604~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604-debuginfo", rpm:"libns1604-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bind", rpm:"python3-bind~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysuser-shadow", rpm:"sysuser-shadow~2.0~4.2.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysuser-tools", rpm:"sysuser-tools~2.0~4.2.8", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.16.6~12.32.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600", rpm:"libbind9-1600~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600-debuginfo", rpm:"libbind9-1600-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605", rpm:"libdns1605~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605-debuginfo", rpm:"libdns1605-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs-devel", rpm:"libirs-devel~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601", rpm:"libirs1601~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601-debuginfo", rpm:"libirs1601-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606", rpm:"libisc1606~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606-debuginfo", rpm:"libisc1606-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600", rpm:"libisccc1600~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600-debuginfo", rpm:"libisccc1600-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600", rpm:"libisccfg1600~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600-debuginfo", rpm:"libisccfg1600-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604", rpm:"libns1604~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604-debuginfo", rpm:"libns1604-debuginfo~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bind", rpm:"python3-bind~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysuser-shadow", rpm:"sysuser-shadow~2.0~4.2.8", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysuser-tools", rpm:"sysuser-tools~2.0~4.2.8", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.16.6~12.32.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.16.6~12.32.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.16.6~12.32.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.16.6~12.32.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.16.6~12.32.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.16.6~12.32.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600", rpm:"libbind9-1600~9.16.6~12.32.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605", rpm:"libdns1605~9.16.6~12.32.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs-devel", rpm:"libirs-devel~9.16.6~12.32.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601", rpm:"libirs1601~9.16.6~12.32.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606", rpm:"libisc1606~9.16.6~12.32.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600", rpm:"libisccc1600~9.16.6~12.32.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600", rpm:"libisccfg1600~9.16.6~12.32.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604", rpm:"libns1604~9.16.6~12.32.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bind", rpm:"python3-bind~9.16.6~12.32.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysuser-shadow", rpm:"sysuser-shadow~2.0~4.2.8", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysuser-tools", rpm:"sysuser-tools~2.0~4.2.8", rls:"SLES15.0"))) {
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
