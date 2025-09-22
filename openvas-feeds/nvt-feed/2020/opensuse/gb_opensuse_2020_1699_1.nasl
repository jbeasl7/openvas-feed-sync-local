# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.853509");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2017-3136", "CVE-2018-5741", "CVE-2019-6477", "CVE-2020-8616", "CVE-2020-8617", "CVE-2020-8618", "CVE-2020-8619", "CVE-2020-8620", "CVE-2020-8621", "CVE-2020-8622", "CVE-2020-8623", "CVE-2020-8624");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-20 12:15:00 +0000 (Tue, 20 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-21 03:06:16 +0000 (Wed, 21 Oct 2020)");
  script_name("openSUSE: Security Advisory for bind (openSUSE-SU-2020:1699-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1699-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-10/msg00041.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bind'
  package(s) announced via the openSUSE-SU-2020:1699-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for bind fixes the following issues:

  BIND was upgraded to version 9.16.6:

  Note:

  - bind is now more strict in regards to DNSSEC. If queries are not
  working, check for DNSSEC issues. For instance, if bind is used in a
  namserver forwarder chain, the forwarding DNS servers must support
  DNSSEC.

  Fixing security issues:

  - CVE-2020-8616: Further limit the number of queries that can be triggered
  from a request.  Root and TLD servers are no longer exempt from
  max-recursion-queries.  Fetches for missing name server. (bsc#1171740)
  Address records are limited to 4 for any domain.

  - CVE-2020-8617: Replaying a TSIG BADTIME response as a request could
  trigger an assertion failure. (bsc#1171740)

  - CVE-2019-6477: Fixed an issue where TCP-pipelined queries could bypass
  the tcp-clients limit (bsc#1157051).

  - CVE-2018-5741: Fixed the documentation (bsc#1109160).

  - CVE-2020-8618: It was possible to trigger an INSIST when determining
  whether a record would fit into a TCP message buffer (bsc#1172958).

  - CVE-2020-8619: It was possible to trigger an INSIST in
  lib/dns/rbtdb.c:new_reference() with a particular zone content and query
  patterns (bsc#1172958).

  - CVE-2020-8624: 'update-policy' rules of type 'subdomain' were
  incorrectly treated as 'zonesub' rules, which allowed keys used in
  'subdomain' rules to update names outside
  of the specified subdomains. The problem was fixed by making sure
  'subdomain' rules are again processed as described in the ARM
  (bsc#1175443).

  - CVE-2020-8623: When BIND 9 was compiled with native PKCS#11 support, it
  was possible to trigger an assertion failure in code determining the
  number of bits in the PKCS#11 RSA public key with a specially crafted
  packet (bsc#1175443).

  - CVE-2020-8621: named could crash in certain query resolution scenarios
  where QNAME minimization and forwarding were both enabled (bsc#1175443).

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

  - Installed the default files in /var/lib/named and c ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'bind' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"bind", rpm:"bind~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-chrootenv", rpm:"bind-chrootenv~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debuginfo", rpm:"bind-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-debugsource", rpm:"bind-debugsource~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel", rpm:"bind-devel~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils", rpm:"bind-utils~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-utils-debuginfo", rpm:"bind-utils-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600", rpm:"libbind9-1600~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600-debuginfo", rpm:"libbind9-1600-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605", rpm:"libdns1605~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605-debuginfo", rpm:"libdns1605-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs-devel", rpm:"libirs-devel~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601", rpm:"libirs1601~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601-debuginfo", rpm:"libirs1601-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606", rpm:"libisc1606~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606-debuginfo", rpm:"libisc1606-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600", rpm:"libisccc1600~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600-debuginfo", rpm:"libisccc1600-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600", rpm:"libisccfg1600~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600-debuginfo", rpm:"libisccfg1600-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604", rpm:"libns1604~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604-debuginfo", rpm:"libns1604-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuv-debugsource", rpm:"libuv-debugsource~1.18.0~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuv-devel", rpm:"libuv-devel~1.18.0~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuv1", rpm:"libuv1~1.18.0~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuv1-debuginfo", rpm:"libuv1-debuginfo~1.18.0~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-doc", rpm:"bind-doc~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-bind", rpm:"python3-bind~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysuser-shadow", rpm:"sysuser-shadow~2.0~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"sysuser-tools", rpm:"sysuser-tools~2.0~lp152.5.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bind-devel-32bit", rpm:"bind-devel-32bit~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600-32bit", rpm:"libbind9-1600-32bit~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbind9-1600-32bit-debuginfo", rpm:"libbind9-1600-32bit-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605-32bit", rpm:"libdns1605-32bit~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libdns1605-32bit-debuginfo", rpm:"libdns1605-32bit-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601-32bit", rpm:"libirs1601-32bit~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libirs1601-32bit-debuginfo", rpm:"libirs1601-32bit-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606-32bit", rpm:"libisc1606-32bit~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisc1606-32bit-debuginfo", rpm:"libisc1606-32bit-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600-32bit", rpm:"libisccc1600-32bit~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccc1600-32bit-debuginfo", rpm:"libisccc1600-32bit-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600-32bit", rpm:"libisccfg1600-32bit~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libisccfg1600-32bit-debuginfo", rpm:"libisccfg1600-32bit-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604-32bit", rpm:"libns1604-32bit~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libns1604-32bit-debuginfo", rpm:"libns1604-32bit-debuginfo~9.16.6~lp152.14.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuv1-32bit", rpm:"libuv1-32bit~1.18.0~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libuv1-32bit-debuginfo", rpm:"libuv1-32bit-debuginfo~1.18.0~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
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