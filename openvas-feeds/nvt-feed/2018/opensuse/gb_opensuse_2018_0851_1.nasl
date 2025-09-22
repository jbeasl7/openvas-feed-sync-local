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
  script_oid("1.3.6.1.4.1.25623.1.0.851728");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-03-30 08:40:53 +0200 (Fri, 30 Mar 2018)");
  script_cve_id("CVE-2016-9941", "CVE-2016-9942", "CVE-2018-7225");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-23 13:15:00 +0000 (Fri, 23 Oct 2020)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for LibVNCServer (openSUSE-SU-2018:0851-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'LibVNCServer'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"LibVNCServer was updated to fix two security issues.

  These security issues were fixed:

  - CVE-2018-7225: Missing input sanitization inside rfbserver.c
  rfbProcessClientNormalMessage() (bsc#1081493).

  - CVE-2016-9942: Heap-based buffer overflow in ultra.c allowed remote
  servers to cause a denial of service (application crash) or possibly
  execute arbitrary code via a crafted FramebufferUpdate message with the
  Ultra type tile, such that the LZO payload decompressed length exceeds
  what is specified by the tile dimensions (bsc#1017712).

  - CVE-2016-9941: Heap-based buffer overflow in rfbproto.c allowed remote
  servers to cause a denial of service (application crash) or possibly
  execute arbitrary code via a crafted FramebufferUpdate message
  containing a subrectangle outside of the client drawing area
  (bsc#1017711).

  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-326=1");

  script_tag(name:"affected", value:"LibVNCServer on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:0851-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-03/msg00073.html");
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
  if(!isnull(res = isrpmvuln(pkg:"LibVNCServer-debugsource", rpm:"LibVNCServer-debugsource~0.9.9~16.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"LibVNCServer-devel", rpm:"LibVNCServer-devel~0.9.9~16.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncclient0", rpm:"libvncclient0~0.9.9~16.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncclient0-debuginfo", rpm:"libvncclient0-debuginfo~0.9.9~16.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver0", rpm:"libvncserver0~0.9.9~16.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvncserver0-debuginfo", rpm:"libvncserver0-debuginfo~0.9.9~16.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linuxvnc", rpm:"linuxvnc~0.9.9~16.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"linuxvnc-debuginfo", rpm:"linuxvnc-debuginfo~0.9.9~16.3.1", rls:"openSUSELeap42.3"))) {
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
