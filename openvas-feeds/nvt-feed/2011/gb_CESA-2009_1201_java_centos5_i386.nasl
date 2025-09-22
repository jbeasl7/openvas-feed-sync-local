# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-August/016065.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880916");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_xref(name:"CESA", value:"2009:1201");
  script_cve_id("CVE-2009-0217", "CVE-2009-2475", "CVE-2009-2476", "CVE-2009-2625", "CVE-2009-2670", "CVE-2009-2671", "CVE-2009-2672", "CVE-2009-2673", "CVE-2009-2674", "CVE-2009-2675", "CVE-2009-2689", "CVE-2009-2690");
  script_name("CentOS Update for java CESA-2009:1201 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'java'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"java on CentOS 5");
  script_tag(name:"insight", value:"These packages provide the OpenJDK 6 Java Runtime Environment and the
  OpenJDK 6 Software Development Kit. The Java Runtime Environment (JRE)
  contains the software and tools that users need to run applications written
  using the Java programming language.

  A flaw was found in the way the XML Digital Signature implementation in the
  JRE handled HMAC-based XML signatures. An attacker could use this flaw to
  create a crafted signature that could allow them to bypass authentication,
  or trick a user, applet, or application into accepting untrusted content.
  (CVE-2009-0217)

  Several potential information leaks were found in various mutable static
  variables. These could be exploited in application scenarios that execute
  untrusted scripting code. (CVE-2009-2475)

  It was discovered that OpenType checks can be bypassed. This could allow a
  rogue application to bypass access restrictions by acquiring references to
  privileged objects through finalizer resurrection. (CVE-2009-2476)

  A denial of service flaw was found in the way the JRE processes XML. A
  remote attacker could use this flaw to supply crafted XML that would lead
  to a denial of service. (CVE-2009-2625)

  A flaw was found in the JRE audio system. An untrusted applet or
  application could use this flaw to gain read access to restricted System
  properties. (CVE-2009-2670)

  Two flaws were found in the JRE proxy implementation. An untrusted applet
  or application could use these flaws to discover the usernames of users
  running applets and applications, or obtain web browser cookies and use
  them for session hijacking attacks. (CVE-2009-2671, CVE-2009-2672)

  An additional flaw was found in the proxy mechanism implementation. This
  flaw allowed an untrusted applet or application to bypass access
  restrictions and communicate using non-authorized socket or URL connections
  to hosts other than the origin host. (CVE-2009-2673)

  An integer overflow flaw was found in the way the JRE processes JPEG
  images. An untrusted application could use this flaw to extend its
  privileges, allowing it to read and write local files, as well as to
  execute local applications with the privileges of the user running the
  application. (CVE-2009-2674)

  An integer overflow flaw was found in the JRE unpack200 functionality. An
  untrusted applet or application could extend its privileges, allowing it to
  read and write local files, as well as to execute local applications with
  the privileges of the user running the applet or application. (CVE-2009-2675)

  It was discovered that JDK13Services grants unnecess ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "CentOS5") {
  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk", rpm:"java-1.6.0-openjdk~1.6.0.0~1.2.b09.el5", rls:"CentOS5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-demo", rpm:"java-1.6.0-openjdk-demo~1.6.0.0~1.2.b09.el5", rls:"CentOS5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-devel", rpm:"java-1.6.0-openjdk-devel~1.6.0.0~1.2.b09.el5", rls:"CentOS5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-javadoc", rpm:"java-1.6.0-openjdk-javadoc~1.6.0.0~1.2.b09.el5", rls:"CentOS5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"java-1.6.0-openjdk-src", rpm:"java-1.6.0-openjdk-src~1.6.0.0~1.2.b09.el5", rls:"CentOS5"))) {
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
