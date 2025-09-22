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
  script_oid("1.3.6.1.4.1.25623.1.0.851829");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-08-02 05:48:43 +0200 (Thu, 02 Aug 2018)");
  script_cve_id("CVE-2015-3243");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-31 19:07:00 +0000 (Mon, 31 Jul 2017)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for rsyslog (openSUSE-SU-2018:2166-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsyslog'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for rsyslog fixes the following issues:

  The following security vulnerability was addressed:

  CVE-2015-3243: Make sure that log files are not created world-readable
  (bsc#935393)

  This update was imported from the SUSE:SLE-12-SP3:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-789=1");

  script_tag(name:"affected", value:"rsyslog on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:2166-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00001.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"rsyslog", rpm:"rsyslog~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-debuginfo", rpm:"rsyslog-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-debugsource", rpm:"rsyslog-debugsource~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-diag-tools", rpm:"rsyslog-diag-tools~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-diag-tools-debuginfo", rpm:"rsyslog-diag-tools-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-doc", rpm:"rsyslog-doc~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-dbi", rpm:"rsyslog-module-dbi~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-dbi-debuginfo", rpm:"rsyslog-module-dbi-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-elasticsearch", rpm:"rsyslog-module-elasticsearch~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-elasticsearch-debuginfo", rpm:"rsyslog-module-elasticsearch-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gcrypt", rpm:"rsyslog-module-gcrypt~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gcrypt-debuginfo", rpm:"rsyslog-module-gcrypt-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gssapi", rpm:"rsyslog-module-gssapi~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gssapi-debuginfo", rpm:"rsyslog-module-gssapi-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gtls", rpm:"rsyslog-module-gtls~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-gtls-debuginfo", rpm:"rsyslog-module-gtls-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-guardtime", rpm:"rsyslog-module-guardtime~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-guardtime-debuginfo", rpm:"rsyslog-module-guardtime-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-mmnormalize", rpm:"rsyslog-module-mmnormalize~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-mmnormalize-debuginfo", rpm:"rsyslog-module-mmnormalize-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-mysql", rpm:"rsyslog-module-mysql~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-mysql-debuginfo", rpm:"rsyslog-module-mysql-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-omamqp1", rpm:"rsyslog-module-omamqp1~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-omamqp1-debuginfo", rpm:"rsyslog-module-omamqp1-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-omhttpfs", rpm:"rsyslog-module-omhttpfs~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-omhttpfs-debuginfo", rpm:"rsyslog-module-omhttpfs-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-omtcl", rpm:"rsyslog-module-omtcl~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-omtcl-debuginfo", rpm:"rsyslog-module-omtcl-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-pgsql", rpm:"rsyslog-module-pgsql~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-pgsql-debuginfo", rpm:"rsyslog-module-pgsql-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-relp", rpm:"rsyslog-module-relp~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-relp-debuginfo", rpm:"rsyslog-module-relp-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-snmp", rpm:"rsyslog-module-snmp~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-snmp-debuginfo", rpm:"rsyslog-module-snmp-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rsyslog-module-udpspoof", rpm:"rsyslog-module-udpspoof~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"syslog-module-udpspoof-debuginfo", rpm:"syslog-module-udpspoof-debuginfo~8.24.0~2.3.1", rls:"openSUSELeap42.3"))) {
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
