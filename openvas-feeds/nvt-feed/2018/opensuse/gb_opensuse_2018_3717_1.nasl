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
  script_oid("1.3.6.1.4.1.25623.1.0.852119");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2016-10209", "CVE-2016-10349", "CVE-2016-10350", "CVE-2017-14166",
                "CVE-2017-14501", "CVE-2017-14502", "CVE-2017-14503");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-11-10 05:59:19 +0100 (Sat, 10 Nov 2018)");
  script_name("openSUSE: Security Advisory for libarchive (openSUSE-SU-2018:3717-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"openSUSE-SU", value:"2018:3717-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-11/msg00017.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive'
  package(s) announced via the openSUSE-SU-2018:3717-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libarchive fixes the following issues:

  - CVE-2016-10209: The archive_wstring_append_from_mbs function in
  archive_string.c allowed remote attackers to cause a denial of service
  (NULL pointer dereference and application crash) via a crafted archive
  file. (bsc#1032089)

  - CVE-2016-10349: The archive_le32dec function in archive_endian.h allowed
  remote attackers to cause a denial of service (heap-based buffer
  over-read and application crash) via a crafted file. (bsc#1037008)

  - CVE-2016-10350: The archive_read_format_cab_read_header function in
  archive_read_support_format_cab.c allowed remote attackers to cause a
  denial of service (heap-based buffer over-read and application crash)
  via a crafted file. (bsc#1037009)

  - CVE-2017-14166: libarchive allowed remote attackers to cause a denial of
  service (xml_data heap-based buffer over-read and application crash) via
  a crafted xar archive, related to the mishandling of empty strings in
  the atol8 function in archive_read_support_format_xar.c. (bsc#1057514)

  - CVE-2017-14501: An out-of-bounds read flaw existed in parse_file_info in
  archive_read_support_format_iso9660.c when extracting a specially
  crafted iso9660 iso file, related to
  archive_read_format_iso9660_read_header. (bsc#1059139)

  - CVE-2017-14502: read_header in archive_read_support_format_rar.c
  suffered from an off-by-one error for UTF-16 names in RAR archives,
  leading to an out-of-bounds read in archive_read_format_rar_read_header.
  (bsc#1059134)

  - CVE-2017-14503: libarchive suffered from an out-of-bounds read within
  lha_read_data_none() in archive_read_support_format_lha.c when
  extracting a specially crafted lha archive, related to lha_crc16.
  (bsc#1059100)


  This update was imported from the SUSE:SLE-12:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2018-1366=1");

  script_tag(name:"affected", value:"libarchive on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3") {
  if(!isnull(res = isrpmvuln(pkg:"bsdtar", rpm:"bsdtar~3.1.2~20.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdtar-debuginfo", rpm:"bsdtar-debuginfo~3.1.2~20.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-debugsource", rpm:"libarchive-debugsource~3.1.2~20.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-devel", rpm:"libarchive-devel~3.1.2~20.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13", rpm:"libarchive13~3.1.2~20.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13-debuginfo", rpm:"libarchive13-debuginfo~3.1.2~20.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13-32bit", rpm:"libarchive13-32bit~3.1.2~20.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13-debuginfo-32bit", rpm:"libarchive13-debuginfo-32bit~3.1.2~20.3.1", rls:"openSUSELeap42.3"))) {
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
