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
  script_oid("1.3.6.1.4.1.25623.1.0.853125");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2019-10067", "CVE-2019-12248", "CVE-2019-12497", "CVE-2019-12746", "CVE-2019-13457", "CVE-2019-13458", "CVE-2019-16375", "CVE-2019-18179", "CVE-2019-18180", "CVE-2019-9752", "CVE-2019-9892", "CVE-2020-1765", "CVE-2020-1766", "CVE-2020-1769", "CVE-2020-1770", "CVE-2020-1771", "CVE-2020-1772", "CVE-2020-1773");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-23 15:15:00 +0000 (Wed, 23 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-04-26 03:00:44 +0000 (Sun, 26 Apr 2020)");
  script_name("openSUSE: Security Advisory for Recommended (openSUSE-SU-2020:0551-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0551-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-04/msg00038.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Recommended'
  package(s) announced via the openSUSE-SU-2020:0551-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Otrs was updated to 5.0.42, fixing lots of bugs and security issues:

  - CVE-2020-1773 boo#1168029 OSA-2020-10:

  * Session / Password / Password token leak An attacker with the ability
  to generate session IDs or password reset tokens, either by being able
  to authenticate or by exploiting OSA-2020-09, may be able to predict
  other users session IDs, password reset tokens and automatically
  generated passwords.

  - CVE-2020-1772 boo#1168029 OSA-2020-09:

  - CVE-2020-1771 boo#1168030 OSA-2020-08:

  * Possible XSS in Customer user address book Attacker is able craft an
  article with a link to the customer address book with malicious
  content (JavaScript). When agent opens the link, JavaScript code is
  executed due to the missing parameter encoding.

  - CVE-2020-1770 boo#1168031 OSA-2020-07:

  * Information disclosure in support bundle files Support bundle
  generated files could contain sensitive information that might be
  unwanted to be disclosed.

  - CVE-2020-1769 boo#1168032 OSA-2020-06:

  * Autocomplete in the form login screens In the login screens (in agent
  and customer interface), Username and Password fields use
  autocomplete, which might be considered as security issue.


  * bug#14912 - Installer refers to non-existing documentation

  - added code to upgrade OTRS from 4 to 5

  READ UPGRADING.SUSE

  * steps 1 to 4 are done by rpm pkg

  * steps 5 to *END* need to be done manually cause of DB backup

  Update to 5.0.40


  - CVE-2020-1766 boo#1160663 OSA-2020-02: Improper handling of uploaded
  inline images Due to improper handling of uploaded images it is possible
  in very unlikely and rare conditions to force the agents browser to
  execute malicious javascript from a special crafted SVG file rendered as
  inline jpg file.

  * CVE-2020-1765, OSA-2020-01: Spoofing of From field in several screens
  An improper control of parameter ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'Recommended' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"otrs", rpm:"otrs~5.0.42~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"otrs-doc", rpm:"otrs-doc~5.0.42~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"otrs-itsm", rpm:"otrs-itsm~5.0.42~lp151.2.3.1", rls:"openSUSELeap15.1"))) {
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
