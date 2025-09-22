# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852063");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-11469", "CVE-2018-14645");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-23 08:15:00 +0000 (Tue, 23 Jul 2019)");
  script_tag(name:"creation_date", value:"2018-10-26 06:40:34 +0200 (Fri, 26 Oct 2018)");
  script_name("openSUSE: Security Advisory for haproxy (openSUSE-SU-2018:3324-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2018:3324-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00050.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'haproxy'
  package(s) announced via the openSUSE-SU-2018:3324-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for haproxy to version 1.8.14 fixes the following issues:

  These security issues were fixed:

  - CVE-2018-14645: A flaw was discovered in the HPACK decoder what caused an
  out-of-bounds read in hpack_valid_idx() that resulted in a remote crash
  and denial of service (bsc#1108683)

  - CVE-2018-11469: Incorrect caching of responses to requests including an
  Authorization header allowed attackers to achieve information disclosure
  via an unauthenticated remote request (bsc#1094846).

  These non-security issues were fixed:

  - Require apparmor-abstractions to reduce dependencies (bsc#1100787)

  - hpack: fix improper sign check on the header index value

  - cli: make sure the 'getsock' command is only called on connections

  - tools: fix set_net_port() / set_host_port() on IPv4

  - patterns: fix possible double free when reloading a pattern list

  - server: Crash when setting FQDN via CLI.

  - kqueue: Don't reset the changes number by accident.

  - snapshot: take the proxy's lock while dumping errors

  - http/threads: atomically increment the error snapshot ID

  - dns: check and link servers' resolvers right after config parsing

  - h2: fix risk of memory leak on malformated wrapped frames

  - session: fix reporting of handshake processing time in the logs

  - stream: use atomic increments for the request counter

  - thread: implement HA_ATOMIC_XADD()

  - ECC cert should work with TLS   v1.2 and openssl  = 1.1.1

  - dns/server: fix incomatibility between SRV resolution and server state
  file

  - hlua: Don't call RESET_SAFE_LJMP if SET_SAFE_LJMP returns 0.

  - thread: lua: Wrong SSL context initialization.

  - hlua: Make sure we drain the output buffer when done.

  - lua: reset lua transaction between http requests

  - mux_pt: dereference the connection with care in mux_pt_wake()

  - lua: Bad HTTP client request duration.

  - unix: provide a - drain() function

  - Fix spelling error in configuration doc

  - cli/threads: protect some server commands against concurrent operations

  - cli/threads: protect all 'proxy' commands against concurrent updates

  - lua: socket timeouts are not applied

  - ssl: Use consistent naming for TLS protocols

  - dns: explain set server ... fqdn requires resolver

  - map: fix map_regm with backref

  - ssl: loading dh param from certifile causes unpredictable error.

  - ssl: fix missing error loading a keytype cert from a bundle.

  - ssl: empty connections reported as errors.

  - cli: make 'show fd' thread-safe

  - hathreads: implement a more flexible rendez-vous point

  - threads: fix the no-thread case after the change to the sync point
  ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"haproxy on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {
  if(!isnull(res = isrpmvuln(pkg:"haproxy", rpm:"haproxy~1.8.14~git0.52e4d43b~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-debuginfo", rpm:"haproxy-debuginfo~1.8.14~git0.52e4d43b~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"haproxy-debugsource", rpm:"haproxy-debugsource~1.8.14~git0.52e4d43b~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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
