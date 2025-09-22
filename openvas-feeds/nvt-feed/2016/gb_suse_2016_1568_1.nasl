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
  script_oid("1.3.6.1.4.1.25623.1.0.851336");
  script_version("2021-10-11T13:01:25+0000");
  script_tag(name:"last_modification", value:"2021-10-11 13:01:25 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-06-15 05:21:21 +0200 (Wed, 15 Jun 2016)");
  script_cve_id("CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7974", "CVE-2016-1547",
                "CVE-2016-1548", "CVE-2016-1549", "CVE-2016-1550", "CVE-2016-1551",
                "CVE-2016-2516", "CVE-2016-2517", "CVE-2016-2518", "CVE-2016-2519",
                "CVE-2016-4953", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956",
                "CVE-2016-4957");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 13:15:00 +0000 (Fri, 16 Jul 2021)");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for ntp (SUSE-SU-2016:1568-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ntp was updated to version 4.2.8p8 to fix 17 security issues.

  These security issues were fixed:

  - CVE-2016-4956: Broadcast interleave (bsc#982068).

  - CVE-2016-2518: Crafted addpeer with hmode   7 causes array wraparound
  with MATCH_ASSOC (bsc#977457).

  - CVE-2016-2519: ctl_getitem() return value not always checked
  (bsc#977458).

  - CVE-2016-4954: Processing spoofed server packets (bsc#982066).

  - CVE-2016-4955: Autokey association reset (bsc#982067).

  - CVE-2015-7974: NTP did not verify peer associations of symmetric keys
  when authenticating packets, which might allowed remote attackers to
  conduct impersonation attacks via an arbitrary trusted key, aka a
  'skeleton key (bsc#962960).

  - CVE-2016-4957: CRYPTO_NAK crash (bsc#982064).

  - CVE-2016-2516: Duplicate IPs on unconfig directives will cause an
  assertion botch (bsc#977452).

  - CVE-2016-2517: Remote configuration trustedkey/requestkey values are not
  properly validated (bsc#977455).

  - CVE-2016-4953: Bad authentication demobilizes ephemeral associations
  (bsc#982065).

  - CVE-2016-1547: CRYPTO-NAK DoS (bsc#977459).

  - CVE-2016-1551: Refclock impersonation vulnerability, AKA:
  refclock-peering (bsc#977450).

  - CVE-2016-1550: Improve NTP security against buffer comparison timing
  attacks, authdecrypt-timing, AKA: authdecrypt-timing (bsc#977464).

  - CVE-2016-1548: Interleave-pivot - MITIGATION ONLY (bsc#977461).

  - CVE-2016-1549: Sybil vulnerability: ephemeral association attack, AKA:
  ntp-sybil - MITIGATION ONLY (bsc#977451).

  This release also contained improved patches for CVE-2015-7704,
  CVE-2015-7705, CVE-2015-7974.

  These non-security issues were fixed:

  - bsc#979302: Change the process name of the forking DNS worker process to
  avoid the impression that ntpd is started twice.

  - bsc#981422: Don't ignore SIGCHILD because it breaks wait().

  - bsc#979981: ntp-wait does not accept fractional seconds, so use 1
  instead of 0.2 in ntp-wait.service.

  - Separate the creation of ntp.keys and key #1 in it to avoid problems
  when upgrading installations that have the file, but no key #1, which is
  needed e.g. by 'rcntp addserver'.

  - bsc#957226: Restrict the parser in the startup script to the first
  occurrence of 'keys' and 'controlkey' in ntp.conf.");

  script_tag(name:"affected", value:"ntp on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"SUSE-SU", value:"2016:1568-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(SLED12\.0SP0|SLES12\.0SP0)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLED12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p8~46.8.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.8p8~46.8.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debugsource", rpm:"ntp-debugsource~4.2.8p8~46.8.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p8~46.8.1", rls:"SLED12.0SP0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP0") {
  if(!isnull(res = isrpmvuln(pkg:"ntp", rpm:"ntp~4.2.8p8~46.8.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debuginfo", rpm:"ntp-debuginfo~4.2.8p8~46.8.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-debugsource", rpm:"ntp-debugsource~4.2.8p8~46.8.1", rls:"SLES12.0SP0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ntp-doc", rpm:"ntp-doc~4.2.8p8~46.8.1", rls:"SLES12.0SP0"))) {
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
