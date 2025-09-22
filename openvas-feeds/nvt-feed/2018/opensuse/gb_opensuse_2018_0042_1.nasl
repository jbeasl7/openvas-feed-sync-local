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
  script_oid("1.3.6.1.4.1.25623.1.0.851679");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-01-09 15:38:23 +0100 (Tue, 09 Jan 2018)");
  script_cve_id("CVE-2016-10165", "CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842",
                "CVE-2016-9843", "CVE-2017-10053", "CVE-2017-10067", "CVE-2017-10074",
                "CVE-2017-10081", "CVE-2017-10086", "CVE-2017-10087", "CVE-2017-10089",
                "CVE-2017-10090", "CVE-2017-10096", "CVE-2017-10101", "CVE-2017-10102",
                "CVE-2017-10105", "CVE-2017-10107", "CVE-2017-10108", "CVE-2017-10109",
                "CVE-2017-10110", "CVE-2017-10111", "CVE-2017-10114", "CVE-2017-10115",
                "CVE-2017-10116", "CVE-2017-10118", "CVE-2017-10125", "CVE-2017-10135",
                "CVE-2017-10176", "CVE-2017-10193", "CVE-2017-10198", "CVE-2017-10243",
                "CVE-2017-10274", "CVE-2017-10281", "CVE-2017-10285", "CVE-2017-10295",
                "CVE-2017-10345", "CVE-2017-10346", "CVE-2017-10347", "CVE-2017-10348",
                "CVE-2017-10349", "CVE-2017-10350", "CVE-2017-10355", "CVE-2017-10356",
                "CVE-2017-10357", "CVE-2017-10388");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-22 17:16:00 +0000 (Wed, 22 Jun 2022)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for java-1_7_0-openjdk (openSUSE-SU-2018:0042-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java-1_7_0-openjdk'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for java-1_7_0-openjdk fixes the following issues:

  Security issues fixed:

  - CVE-2017-10356: Fix issue inside subcomponent Security (bsc#1064084).

  - CVE-2017-10274: Fix issue inside subcomponent Smart Card IO
  (bsc#1064071).

  - CVE-2017-10281: Fix issue inside subcomponent Serialization
  (bsc#1064072).

  - CVE-2017-10285: Fix issue inside subcomponent RMI (bsc#1064073).

  - CVE-2017-10295: Fix issue inside subcomponent Networking (bsc#1064075).

  - CVE-2017-10388: Fix issue inside subcomponent Libraries (bsc#1064086).

  - CVE-2017-10346: Fix issue inside subcomponent Hotspot (bsc#1064078).

  - CVE-2017-10350: Fix issue inside subcomponent JAX-WS (bsc#1064082).

  - CVE-2017-10347: Fix issue inside subcomponent Serialization
  (bsc#1064079).

  - CVE-2017-10349: Fix issue inside subcomponent JAXP (bsc#1064081).

  - CVE-2017-10345: Fix issue inside subcomponent Serialization
  (bsc#1064077).

  - CVE-2017-10348: Fix issue inside subcomponent Libraries (bsc#1064080).

  - CVE-2017-10357: Fix issue inside subcomponent Serialization
  (bsc#1064085).

  - CVE-2017-10355: Fix issue inside subcomponent Networking (bsc#1064083).

  - CVE-2017-10102: Fix incorrect handling of references in DGC
  (bsc#1049316).

  - CVE-2017-10053: Fix reading of unprocessed image data in JPEGImageReader
  (bsc#1049305).

  - CVE-2017-10067: Fix JAR verifier incorrect handling of missing digest
  (bsc#1049306).

  - CVE-2017-10081: Fix incorrect bracket processing in function signature
  handling (bsc#1049309).

  - CVE-2017-10087: Fix insufficient access control checks in
  ThreadPoolExecutor (bsc#1049311).

  - CVE-2017-10089: Fix insufficient access control checks in
  ServiceRegistry (bsc#1049312).

  - CVE-2017-10090: Fix insufficient access control checks in
  AsynchronousChannelGroupImpl (bsc#1049313).

  - CVE-2017-10096: Fix insufficient access control checks in XML
  transformations (bsc#1049314).

  - CVE-2017-10101: Fix unrestricted access to
  com.sun.org.apache.xml.internal.resolver (bsc#1049315).

  - CVE-2017-10107: Fix insufficient access control checks in ActivationID
  (bsc#1049318).

  - CVE-2017-10074: Fix integer overflows in range check loop predicates
  (bsc#1049307).

  - CVE-2017-10110: Fix insufficient access control checks in ImageWatched
  (bsc#1049321).

  - CVE-2017-10108: Fix unbounded memory allocation in BasicAttribute
  deserialization (bsc#1049319).

  - CVE-2017-10109: Fix unbounded memory allocation in CodeSource
  deserialization (bsc#1049320).

  - CVE-2017-10115: Fix unspecified vulnerability in subcomponent JCE
  (bsc#1049324).

  - CVE-2 ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"java-1_7_0-openjdk on openSUSE Leap 42.3, openSUSE Leap 42.2");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:0042-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-01/msg00025.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap42\.2|openSUSELeap42\.3)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.2") {
  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-accessibility", rpm:"java-1_7_0-openjdk-accessibility~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-bootstrap", rpm:"java-1_7_0-openjdk-bootstrap~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-bootstrap-debuginfo", rpm:"java-1_7_0-openjdk-bootstrap-debuginfo~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-bootstrap-debugsource", rpm:"java-1_7_0-openjdk-bootstrap-debugsource~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-bootstrap-devel", rpm:"java-1_7_0-openjdk-bootstrap-devel~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-bootstrap-devel-debuginfo", rpm:"java-1_7_0-openjdk-bootstrap-devel-debuginfo~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-bootstrap-headless", rpm:"java-1_7_0-openjdk-bootstrap-headless~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-bootstrap-headless-debuginfo", rpm:"java-1_7_0-openjdk-bootstrap-headless-debuginfo~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-debuginfo", rpm:"java-1_7_0-openjdk-debuginfo~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-debugsource", rpm:"java-1_7_0-openjdk-debugsource~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo-debuginfo", rpm:"java-1_7_0-openjdk-demo-debuginfo~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel-debuginfo", rpm:"java-1_7_0-openjdk-devel-debuginfo~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless-debuginfo", rpm:"java-1_7_0-openjdk-headless-debuginfo~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-src", rpm:"java-1_7_0-openjdk-src~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-javadoc", rpm:"java-1_7_0-openjdk-javadoc~1.7.0.161~42.6.1", rls:"openSUSELeap42.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk", rpm:"java-1_7_0-openjdk~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-accessibility", rpm:"java-1_7_0-openjdk-accessibility~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-bootstrap", rpm:"java-1_7_0-openjdk-bootstrap~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-bootstrap-debuginfo", rpm:"java-1_7_0-openjdk-bootstrap-debuginfo~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-bootstrap-debugsource", rpm:"java-1_7_0-openjdk-bootstrap-debugsource~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-bootstrap-devel", rpm:"java-1_7_0-openjdk-bootstrap-devel~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-bootstrap-devel-debuginfo", rpm:"java-1_7_0-openjdk-bootstrap-devel-debuginfo~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-bootstrap-headless", rpm:"java-1_7_0-openjdk-bootstrap-headless~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-bootstrap-headless-debuginfo", rpm:"java-1_7_0-openjdk-bootstrap-headless-debuginfo~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-debuginfo", rpm:"java-1_7_0-openjdk-debuginfo~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-debugsource", rpm:"java-1_7_0-openjdk-debugsource~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo", rpm:"java-1_7_0-openjdk-demo~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-demo-debuginfo", rpm:"java-1_7_0-openjdk-demo-debuginfo~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel", rpm:"java-1_7_0-openjdk-devel~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-devel-debuginfo", rpm:"java-1_7_0-openjdk-devel-debuginfo~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless", rpm:"java-1_7_0-openjdk-headless~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-headless-debuginfo", rpm:"java-1_7_0-openjdk-headless-debuginfo~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-src", rpm:"java-1_7_0-openjdk-src~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1_7_0-openjdk-javadoc", rpm:"java-1_7_0-openjdk-javadoc~1.7.0.161~45.1", rls:"openSUSELeap42.3"))) {
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
