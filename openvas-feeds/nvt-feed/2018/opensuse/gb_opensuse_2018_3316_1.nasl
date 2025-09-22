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
  script_oid("1.3.6.1.4.1.25623.1.0.852060");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-12021");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-16 12:29:00 +0000 (Thu, 16 May 2019)");
  script_tag(name:"creation_date", value:"2018-10-26 06:40:23 +0200 (Fri, 26 Oct 2018)");
  script_name("openSUSE: Security Advisory for singularity (openSUSE-SU-2018:3316-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2018:3316-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-10/msg00048.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'singularity'
  package(s) announced via the openSUSE-SU-2018:3316-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Singularity was updated to version 2.6.0,
  bringing features, bugfixes and security fixes.

  Security issues fixed:

  - CVE-2018-12021: Fixed access control on systems supporting overlay file
  system (boo#1100333).

  Highlights of 2.6.0:

  - Allow admin to specify a non-standard location for mksquashfs binary at
  build time with '--with-mksquashfs' option.

  - '--nv' can be made default with all action commands in singularity.conf

  - '--nv' can be controlled by env vars '$SINGULARITY_NV' and
  '$SINGULARITY_NV_OFF'

  - Restore shim init process for proper signal handling and child reaping
    when container is initiated in its own PID namespace

  - Add '-i' option to image.create to specify the inode ratio.

  - Bind '/dev/nvidia*' into the container when the '--nv' flag is used in
  conjunction with the '--contain' flag

  - Add '--no-home' option to not mount user $HOME if it is not the $CWD and
  'mount home = yes' is set.

  - Added support for OAUTH2 Docker registries like Azure Container Registry

  Highlights of 2.5.2:

  - a new `build` command was added to replace `create` + `bootstrap`

  - default image format is squashfs, eliminating the need to specify a size

  - a `localimage` can be used as a build base, including ext3, sandbox, and
  other squashfs images

  - singularity hub can now be used as a base with the uri

  - Restore docker-extract aufs whiteout handling that implements correct
  extraction of docker container layers.

  Bug fixes:

  - Fix 404 when using Arch Linux bootstrap

  - Fix environment variables clearing while starting instances

  - several more bug fixes, see CHANGELOG.md for details

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1223=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2018-1223=1");

  script_tag(name:"affected", value:"singularity on openSUSE Leap 15.0.");

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
  if(!isnull(res = isrpmvuln(pkg:"libsingularity1", rpm:"libsingularity1~2.6.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsingularity1-debuginfo", rpm:"libsingularity1-debuginfo~2.6.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"singularity", rpm:"singularity~2.6.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"singularity-debuginfo", rpm:"singularity-debuginfo~2.6.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"singularity-debugsource", rpm:"singularity-debugsource~2.6.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"singularity-devel", rpm:"singularity-devel~2.6.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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
