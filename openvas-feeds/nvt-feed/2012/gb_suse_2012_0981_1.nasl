# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850308");
  script_version("2022-07-05T11:37:01+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:01 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2012-12-13 17:01:37 +0530 (Thu, 13 Dec 2012)");
  script_cve_id("CVE-2012-3422", "CVE-2012-3423");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"openSUSE-SU", value:"2012:0981-1");
  script_name("openSUSE: Security Advisory for icedtea-web (openSUSE-SU-2012:0981-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icedtea-web'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE11\.4|openSUSE12\.1)");

  script_tag(name:"affected", value:"icedtea-web on openSUSE 12.1, openSUSE 11.4");

  script_tag(name:"insight", value:"- update to 1.2.1 (bnc#773458)

  - Security Updates

  * CVE-2012-3422, RH840592: Potential read from an
  uninitialized memory location

  * CVE-2012-3423, RH841345: Incorrect handling of not
  0-terminated strings

  - NetX

  * PR898: signed applications with big jnlp-file doesn't
  start (webstart affect like 'frozen')

  * PR811: javaws is not handling urls with spaces (and
  other characters needing encoding) correctly

  * 816592: icedtea-web not loading GeoGebra java applets
  in Firefox or Chrome

  - Plugin

  * PR863: Error passing strings to applet methods in
  Chromium

  * PR895: IcedTea-Web searches for missing classes on each
  loadClass or findClass

  * PR518: NPString.utf8characters not guaranteed to be
  nul-terminated

  - Common

  * RH838417: Disambiguate signed applet security prompt
  from certificate warning

  * RH838559: Disambiguate signed applet security prompt
  from certificate warning");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

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

if(release == "openSUSE11.4") {
  if(!isnull(res = isrpmvuln(pkg:"icedtea-web", rpm:"icedtea-web~1.2.1~0.13.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web-debuginfo", rpm:"icedtea-web-debuginfo~1.2.1~0.13.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web-debugsource", rpm:"icedtea-web-debugsource~1.2.1~0.13.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web-javadoc", rpm:"icedtea-web-javadoc~1.2.1~0.13.1", rls:"openSUSE11.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSE12.1") {
  if(!isnull(res = isrpmvuln(pkg:"icedtea-web", rpm:"icedtea-web~1.2.1~6.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web-debuginfo", rpm:"icedtea-web-debuginfo~1.2.1~6.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web-debugsource", rpm:"icedtea-web-debugsource~1.2.1~6.1", rls:"openSUSE12.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web-javadoc", rpm:"icedtea-web-javadoc~1.2.1~6.1", rls:"openSUSE12.1"))) {
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
