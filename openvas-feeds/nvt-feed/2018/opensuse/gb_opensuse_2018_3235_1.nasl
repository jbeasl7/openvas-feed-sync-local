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
  script_oid("1.3.6.1.4.1.25623.1.0.851996");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-3136", "CVE-2018-3139", "CVE-2018-3149", "CVE-2018-3150", "CVE-2018-3157", "CVE-2018-3169", "CVE-2018-3180", "CVE-2018-3183");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 17:33:00 +0000 (Mon, 27 Jun 2022)");
  script_tag(name:"creation_date", value:"2018-10-26 06:32:43 +0200 (Fri, 26 Oct 2018)");
  script_name("openSUSE: Security Advisory for java-11-openjdk (openSUSE-SU-2018:3235-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2018:3235-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00041.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-11-openjdk'
  package(s) announced via the openSUSE-SU-2018:3235-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-11-openjdk fixes the following issues:

  Update to upstream tag jdk-11.0.1+13 (Oracle October 2018 CPU)

  Security fixes:

  - S8202936, CVE-2018-3183, bsc#1112148: Improve script engine support

  - S8199226, CVE-2018-3169, bsc#1112146: Improve field accesses

  - S8199177, CVE-2018-3149, bsc#1112144: Enhance JNDI lookups

  - S8202613, CVE-2018-3180, bsc#1112147: Improve TLS connections stability

  - S8208209, CVE-2018-3180, bsc#1112147: Improve TLS connection stability
  again

  - S8199172, CVE-2018-3150, bsc#1112145: Improve jar attribute checks

  - S8200648, CVE-2018-3157, bsc#1112149: Make midi code more sound

  - S8194534, CVE-2018-3136, bsc#1112142: Manifest better support

  - S8208754, CVE-2018-3136, bsc#1112142: The fix for JDK-8194534 needs
  updates

  - S8196902, CVE-2018-3139, bsc#1112143: Better HTTP Redirection

  Security-In-Depth fixes:

  - S8194546: Choosier FileManagers

  - S8195874: Improve jar specification adherence

  - S8196897: Improve PRNG support

  - S8197881: Better StringBuilder support

  - S8201756: Improve cipher inputs

  - S8203654: Improve cypher state updates

  - S8204497: Better formatting of decimals

  - S8200666: Improve LDAP support

  - S8199110: Address Internet Addresses

  Update to upstream tag jdk-11+28 (OpenJDK 11 rc1)

  - S8207317: SSLEngine negotiation fail exception behavior changed from
  fail-fast to fail-lazy

  - S8207838: AArch64: Float registers incorrectly restored in JNI call

  - S8209637: [s390x] Interpreter doesn't call result handler after native
  calls

  - S8209670: CompilerThread releasing code buffer in destructor is unsafe

  - S8209735: Disable avx512 by default

  - S8209806: API docs should be updated to refer to javase11

  - Report version without the '-internal' postfix

  - Don't build against gdk making the accessibility depend on a particular
  version of gtk.

  Update to upstream tag jdk-11+27

  - S8031761: [TESTBUG] Add a regression test for JDK-8026328

  - S8151259: [TESTBUG] nsk/jvmti/RedefineClasses/redefclass030 fails with
  'unexpected values of outer fields of the class' when running with -Xcomp

  - S8164639: Configure PKCS11 tests to use user-supplied NSS libraries

  - S8189667: Desktop#moveToTrash expects incorrect '  ALL FILES  '
  FilePermission

  - S8194949: [Graal] gc/TestNUMAPageSize.java fail with OOM in

  - Xcomp

  - S8195156: [Graal] serviceability/jvmti/GetModulesInfo/
  /JvmtiGetAllModulesTest.java fails with Graal in Xcomp mode

  - S8199081: [Testbug] compiler/linkage/LinkageErrors.java fails if run
  twice

  - S8201394: Update java.se module summary to reflect remov ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"java-11-openjdk on openSUSE Leap 15.0.");

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
  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk", rpm:"java-11-openjdk~11.0.1.0~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-accessibility", rpm:"java-11-openjdk-accessibility~11.0.1.0~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-accessibility-debuginfo", rpm:"java-11-openjdk-accessibility-debuginfo~11.0.1.0~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debuginfo", rpm:"java-11-openjdk-debuginfo~11.0.1.0~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-debugsource", rpm:"java-11-openjdk-debugsource~11.0.1.0~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-demo", rpm:"java-11-openjdk-demo~11.0.1.0~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-devel", rpm:"java-11-openjdk-devel~11.0.1.0~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-headless", rpm:"java-11-openjdk-headless~11.0.1.0~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-jmods", rpm:"java-11-openjdk-jmods~11.0.1.0~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-src", rpm:"java-11-openjdk-src~11.0.1.0~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-11-openjdk-javadoc", rpm:"java-11-openjdk-javadoc~11.0.1.0~lp150.2.6.1", rls:"openSUSELeap15.0"))) {
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
