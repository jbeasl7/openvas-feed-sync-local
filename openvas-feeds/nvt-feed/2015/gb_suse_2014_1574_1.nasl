# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850812");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2015-10-13 18:35:01 +0530 (Tue, 13 Oct 2015)");
  script_cve_id("CVE-2013-6497", "CVE-2014-9050");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SUSE: Security Advisory for clamav (SUSE-SU-2014:1574-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"clamav was updated to version 0.98.5 to fix three security issues and
  several non-security issues.

  These security issues have been fixed:

  * Crash when scanning maliciously crafted yoda's crypter files
  (CVE-2013-6497).

  * Heap-based buffer overflow when scanning encrypted PE files
  (CVE-2014-9050).

  * Crash when using 'clamscan -a'.

  These non-security issues have been fixed:

  * Support for the XDP file format and extracting, decoding, and
  scanning PDF files within XDP files.

  * Addition of shared library support for LLVM versions 3.1 - 3.5 for
  the purpose of just-in-time(JIT) compilation of ClamAV bytecode
  signatures.

  * Enhancements to the clambc command line utility to assist ClamAV
  bytecode signature authors by providing introspection into compiled
  bytecode programs.

  * Resolution of many of the warning messages from ClamAV compilation.

  * Improved detection of malicious PE files.

  * ClamAV 0.98.5 now works with OpenSSL in FIPS compliant mode
  (bnc#904207).

  * Fix server socket setup code in clamd (bnc#903489).

  * Change updateclamconf to prefer the state of the old config file
  even for commented-out options (bnc#903719).

  * Fix infinite loop in clamdscan when clamd is not running.

  * Fix buffer underruns when handling multi-part MIME email attachments.

  * Fix configuration of OpenSSL on various platforms.

  * Fix linking issues with libclamunrar.");

  script_tag(name:"affected", value:"clamav on SUSE Linux Enterprise Server 11 SP3");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"SUSE-SU", value:"2014:1574-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=SLES11\.0SP3");
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
  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.98.5~0.5.1", rls:"SLES11.0SP3"))) {
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
