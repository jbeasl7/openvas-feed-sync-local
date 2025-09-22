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
  script_oid("1.3.6.1.4.1.25623.1.0.853090");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-6459", "CVE-2018-16151", "CVE-2018-17540", "CVE-2018-16152", "CVE-2018-10811", "CVE-2018-5388");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-30 01:15:00 +0000 (Mon, 30 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-30 03:00:41 +0000 (Mon, 30 Mar 2020)");
  script_name("openSUSE: Security Advisory for strongswan (openSUSE-SU-2020:0403-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0403-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-03/msg00047.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'strongswan'
  package(s) announced via the openSUSE-SU-2020:0403-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for strongswan fixes the following issues:

  Strongswan was updated to version 5.8.2 (jsc#SLE-11370).

  Security issue fixed:

  - CVE-2018-6459: Fixed a DoS vulnerability in the parser for PKCS#1
  RSASSA-PSS signatures that was caused by insufficient input validation
  (bsc#1079548).

  Full changelogs:

  Version 5.8.2

  * Identity-based 'CA' constraints, which enforce that the certificate
  chain of the remote peer contains a 'CA' certificate with a specific
  identity, are supported via vici/swanctl.conf. This is similar to the
  existing 'CA' constraints but doesn't require that the 'CA' certificate is
  locally installed, for instance, intermediate 'CA' certificates received
  from the peers. Wildcard identity matching (e.g. ..., OU=Research,
  CN=*) could also be used for the latter but requires trust in the
  intermediate 'CAs' to only issue certificates with legitimate subject
  DNs (e.g. the 'Sales' 'CA' must not issue certificates with
  OU=Research). With the new constraint that's not necessary as long as
  a path length basic constraint (--pathlen for pki --issue) prevents
  intermediate 'CAs' from issuing further intermediate 'CAs'.

  * Intermediate 'CA' certificates may now be sent in hash-and-URL encoding
  by configuring a base URL for the parent 'CA' (#3234,
  swanctl/rw-hash-and-url-multi-level).

  * Implemented NIST SP-800-90A Deterministic Random Bit Generator (DRBG)
  based on AES-CTR and SHA2-HMAC modes. Currently used by the gmp and
  ntru plugins.

  * Random nonces sent in an OCSP requests are now expected in the
  corresponding OCSP responses.

  * The kernel-netlink plugin now ignores deprecated IPv6 addresses for
  MOBIKE. Whether temporary
  or permanent IPv6 addresses are included now depends on the
  charon.prefer_temporary_addrs setting (#3192).

  * Extended Sequence Numbers (ESN) are configured via PF_KEY if supported
  by the kernel.

  * The PF_KEY socket's receive buffer in the kernel-pfkey plugin is now
  cleared before sending requests, as many of the messages sent by the
  kernel are sent as broadcasts to all PF_KEY sockets. This is an issue
  if an external tool is used to manage SAs/policies unrelated to IPsec
  (#3225).

  * The vici plugin now uses unique section names for CHILD_SAs in
  child-updown events (7c74ce9190).

  * For individually deleted CHILD_SAs (in particular for IKEv1) the vici
  child-updown event now includes more information about the CHILD_SAs
  such as traffic statistics (#3198).

  * Custom loggers are correctly re-registered if log levels are changed
  via stroke loglevel (#3182).

  * Avoid lockups during startup on low entropy  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'strongswan' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"strongswan-doc", rpm:"strongswan-doc~5.8.2~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan", rpm:"strongswan~5.8.2~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debuginfo", rpm:"strongswan-debuginfo~5.8.2~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-debugsource", rpm:"strongswan-debugsource~5.8.2~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-hmac", rpm:"strongswan-hmac~5.8.2~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec", rpm:"strongswan-ipsec~5.8.2~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-ipsec-debuginfo", rpm:"strongswan-ipsec-debuginfo~5.8.2~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0", rpm:"strongswan-libs0~5.8.2~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-libs0-debuginfo", rpm:"strongswan-libs0-debuginfo~5.8.2~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-mysql", rpm:"strongswan-mysql~5.8.2~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-mysql-debuginfo", rpm:"strongswan-mysql-debuginfo~5.8.2~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-nm", rpm:"strongswan-nm~5.8.2~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-nm-debuginfo", rpm:"strongswan-nm-debuginfo~5.8.2~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-sqlite", rpm:"strongswan-sqlite~5.8.2~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"strongswan-sqlite-debuginfo", rpm:"strongswan-sqlite-debuginfo~5.8.2~lp151.4.6.1", rls:"openSUSELeap15.1"))) {
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
