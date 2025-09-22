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
  script_oid("1.3.6.1.4.1.25623.1.0.851868");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-08-27 07:20:43 +0200 (Mon, 27 Aug 2018)");
  script_cve_id("CVE-2018-3780");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:40:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for nextcloud (openSUSE-SU-2018:2521-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nextcloud'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nextcloud to version 13.0.5 fixes the following issues:

  Security issues fixed:

  - CVE-2018-3780: Fixed a missing sanitization of search results for an
  autocomplete field that could lead to a stored XSS requiring
  user-interaction. The missing sanitization only affected user names,
  hence malicious search results could only be crafted by authenticated
  users. (boo#1105598)


  Other bugs fixed:

  - Fix highlighting of the upload drop zone

  - Apply ldapUserFilter on members of group

  - Make the DELETION of groups match greedy on the groupID

  - Add parent index to share table

  - Log full exception in cron instead of only the message

  - Properly lock the target file on dav upload when not using part files

  - LDAP backup server should not be queried when auth fails

  - Fix filenames in sharing integration tests

  - Lower log level for quota manipulation cases

  - Let user set avatar in nextcloud if LDAP provides invalid image data

  - Improved logging of smb connection errors

  - Allow admin to disable fetching of avatars as well as a specific
  attribute

  - Allow to disable encryption

  - Update message shown when unsharing a file

  - Fixed English grammatical error on Settings page.

  - Request a valid property for DAV opendir

  - Allow updating the token on session regeneration

  - Prevent lock values from going negative with memcache backend

  - Correctly handle users with numeric user ids

  - Correctly parse the subject parameters for link (un)shares of calendars

  - Fix 'parsing' of email-addresses in comments and chat messages

  - Sanitize parameters in createSessionToken() while logging

  - Also retry rename operation on InvalidArgumentException

  - Improve url detection in comments

  - Only bind to ldap if configuration for the first server is set

  - Use download manager from PDF.js to download the file

  - Fix trying to load removed scripts

  - Only pull for new messages if the session is allowed to be kept alive

  - Always push object data

  - Add prioritization for Talk

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-936=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-936=1");

  script_tag(name:"affected", value:"nextcloud on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:2521-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-08/msg00078.html");
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
  if(!isnull(res = isrpmvuln(pkg:"nextcloud", rpm:"nextcloud~13.0.5~12.1", rls:"openSUSELeap42.3"))) {
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
