# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851323");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2016-06-03 16:25:07 +0530 (Fri, 03 Jun 2016)");
  script_cve_id("CVE-2014-3566", "CVE-2015-8076", "CVE-2015-8077", "CVE-2015-8078");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-16 12:15:00 +0000 (Wed, 16 Jun 2021)");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for cyrus-imapd (SUSE-SU-2016:1457-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cyrus-imapd'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Previous versions of cyrus-imapd would not allow its users to disable
  old protocols like SSLv1 and SSLv2 that are unsafe due to various known
  attacks like BEAST and POODLE.

  The referenced bugtracker item remedies this issue
  by adding the configuration option 'tls_versions' to the imapd.conf
  file.Note that users who upgrade existing installation of this package
  will *not* have their imapd.conf file overwritten, i.e. their IMAP
  server will continue to support SSLv1 and SSLv2 like before. To disable
  support for those protocols, it's necessary to edit imapd.conf manually
  to state 'tls_versions: tls1_0 tls1_1 tls1_2'. New installations,
  however, will have an imapd.conf file that contains these settings
  already, i.e. newly installed IMAP servers do *not* support SSLv1 and
  SSLv2 unless that support is explicitly enabled by the user. (bsc#901748)

  - An integer overflow vulnerability in cyrus-imapd's urlfetch range
  checking code was fixed. (CVE-2015-8076, CVE-2015-8077, CVE-2015-8078,
  bsc#981670, bsc#954200, bsc#954201)

  - Support for Elliptic Curve Diffie-Hellman (ECDH) has been added to
  cyrus-imapd. (bsc#860611).");

  script_tag(name:"affected", value:"cyrus-imapd on SUSE Linux Enterprise Server 12");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"SUSE-SU", value:"2016:1457-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES12\.0SP0");

  script_xref(name:"URL", value:"https://bugzilla.cyrusimap.org/show_bug.cgi?id=3867");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLES12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd-debuginfo", rpm:"cyrus-imapd-debuginfo~2.3.18~37.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-imapd-debugsource", rpm:"cyrus-imapd-debugsource~2.3.18~37.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Cyrus-IMAP", rpm:"perl-Cyrus-IMAP~2.3.18~37.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Cyrus-IMAP-debuginfo", rpm:"perl-Cyrus-IMAP-debuginfo~2.3.18~37.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Cyrus-SIEVE-managesieve", rpm:"perl-Cyrus-SIEVE-managesieve~2.3.18~37.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-Cyrus-SIEVE-managesieve-debuginfo", rpm:"perl-Cyrus-SIEVE-managesieve-debuginfo~2.3.18~37.1", rls:"SLES12.0SP0"))) {
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
