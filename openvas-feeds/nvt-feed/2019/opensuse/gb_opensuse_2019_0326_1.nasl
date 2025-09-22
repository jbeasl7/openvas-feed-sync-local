# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.852343");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-12473", "CVE-2018-12474", "CVE-2018-12476");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:34:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-03-14 04:09:26 +0100 (Thu, 14 Mar 2019)");
  script_name("openSUSE: Security Advisory for obs-service-tar_scm (openSUSE-SU-2019:0326-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:0326-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-03/msg00020.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'obs-service-tar_scm'
  package(s) announced via the openSUSE-SU-2019:0326-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for obs-service-tar_scm fixes the following issues:

  Security vulnerabilities addressed:

  - CVE-2018-12473: Fixed a path traversal issue, which allowed users to
  access files outside of the repository using relative paths (bsc#1105361)

  - CVE-2018-12474: Fixed an issue whereby crafted service parameters
  allowed for unexpected behaviour (bsc#1107507)

  - CVE-2018-12476: Fixed an issue whereby the outfilename parameter allowed
  to write files outside of package directory (bsc#1107944)

  Other bug fixes and changes made:

  - Prefer UTF-8 locale as output format for changes

  - added KankuFile

  - fix problems with unicode source files

  - added python-six to Requires in specfile

  - better encoding handling

  - fixes bsc#1082696 and bsc#1076410

  - fix unicode in containers

  - move to python3

  - added logging for better debugging changesgenerate

  - raise exception if no changesauthor given

  - Stop using @opensuse.org addresses to indicate a missing address

  - move argparse dep to -common package

  - allow submodule and ssl options in appimage

  - sync spec file as used in openSUSE:Tools project

  - check encoding problems for svn and print proper error msg

  - added new param '--locale'

  - separate service file installation in GNUmakefile

  - added glibc as Recommends in spec file

  - cleanup for broken svn caches

  - another fix for unicode problem in obs_scm

  - Final fix for unicode in filenames

  - Another attempt to fix unicode filenames in prep_tree_for_archive

  - Another attempt to fix unicode filenames in prep_tree_for_archive

  - fix bug with unicode filenames in prep_tree_for_archive

  - reuse _service*_servicedata/changes files from previous service runs

  - fix problems with  unicode characters in commit messages for
    changeloggenerate

  - fix encoding issues if commit message contains utf8 char

  - revert encoding for old changes file

  - remove hardcoded utf-8 encodings

  - Add support for extract globbing

  - split pylint2 in GNUmakefile

  - fix check for '--reproducible'

  - create reproducible obscpio archives

  - fix regression from 44b3bee

  - Support also SSH urls for Git

  - check name/version option in obsinfo for slashes

  - check url for remote url

  - check symlinks in subdir parameter

  - check filename for slashes

  - disable follow_symlinks in extract feature

  - switch to obs_scm for this package

  - run download_files in appimage and snapcraft case

  - check --extract file path for parent dir

  - Fix parameter descriptions

  - changed os.removedirs -  shutil.rmtree

  - Adding information regarding the *package-meta ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"obs-service-tar_scm on openSUSE Leap 15.0.");

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
  if(!isnull(res = isrpmvuln(pkg:"obs-service-appimage", rpm:"obs-service-appimage~0.10.5.1551309990.79898c7~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"obs-service-obs_scm", rpm:"obs-service-obs_scm~0.10.5.1551309990.79898c7~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"obs-service-obs_scm-common", rpm:"obs-service-obs_scm-common~0.10.5.1551309990.79898c7~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"obs-service-snapcraft", rpm:"obs-service-snapcraft~0.10.5.1551309990.79898c7~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"obs-service-tar", rpm:"obs-service-tar~0.11.5.1551309990.79898c7~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"obs-service-tar_scm", rpm:"obs-service-tar_scm~0.10.5.1551309990.79898c7~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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
