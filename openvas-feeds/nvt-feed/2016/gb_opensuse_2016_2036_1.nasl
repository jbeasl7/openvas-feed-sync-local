# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851382");
  script_version("2021-10-14T10:01:27+0000");
  script_tag(name:"last_modification", value:"2021-10-14 10:01:27 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-08-12 05:49:33 +0200 (Fri, 12 Aug 2016)");
  script_cve_id("CVE-2015-8918", "CVE-2015-8919", "CVE-2015-8920", "CVE-2015-8921",
                "CVE-2015-8922", "CVE-2015-8923", "CVE-2015-8924", "CVE-2015-8925",
                "CVE-2015-8926", "CVE-2015-8928", "CVE-2015-8929", "CVE-2015-8930",
                "CVE-2015-8931", "CVE-2015-8932", "CVE-2015-8933", "CVE-2015-8934",
                "CVE-2016-4300", "CVE-2016-4301", "CVE-2016-4302", "CVE-2016-4809");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for libarchive (openSUSE-SU-2016:2036-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libarchive'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"libarchive was updated to fix 20 security issues.

  These security issues were fixed:

  - CVE-2015-8918: Overlapping memcpy in CAB parser (bsc#985698).

  - CVE-2015-8919: Heap out of bounds read in LHA/LZH parser (bsc#985697).

  - CVE-2015-8920: Stack out of bounds read in ar parser (bsc#985675).

  - CVE-2015-8921: Global out of bounds read in mtree parser (bsc#985682).

  - CVE-2015-8922: Null pointer access in 7z parser (bsc#985685).

  - CVE-2015-8923: Unclear crashes in ZIP parser (bsc#985703).

  - CVE-2015-8924: Heap buffer read overflow in tar (bsc#985609).

  - CVE-2015-8925: Unclear invalid memory read in mtree parser (bsc#985706).

  - CVE-2015-8926: NULL pointer access in RAR parser (bsc#985704).

  - CVE-2015-8928: Heap out of bounds read in mtree parser (bsc#985679).

  - CVE-2015-8929: Memory leak in tar parser (bsc#985669).

  - CVE-2015-8930: Endless loop in ISO parser (bsc#985700).

  - CVE-2015-8931: Undefined behavior / signed integer overflow in mtree
  parser (bsc#985689).

  - CVE-2015-8932: Compress handler left shifting larger than int size
  (bsc#985665).

  - CVE-2015-8933: Undefined behavior / signed integer overflow in TAR
  parser (bsc#985688).

  - CVE-2015-8934: Out of bounds read in RAR (bsc#985673).

  - CVE-2016-4300: Heap buffer overflow vulnerability in the 7zip
  read_SubStreamsInfo (bsc#985832).

  - CVE-2016-4301: Stack buffer overflow in the mtree parse_device
  (bsc#985826).

  - CVE-2016-4302: Heap buffer overflow in the Rar decompression
  functionality (bsc#985835).

  - CVE-2016-4809: Memory allocate error with symbolic links in cpio
  archives (bsc#984990).

  This update was imported from the SUSE:SLE-12:Update update project.");

  script_tag(name:"affected", value:"libarchive on openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2016:2036-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap42.1") {
  if(!isnull(res = isrpmvuln(pkg:"bsdtar", rpm:"bsdtar~3.1.2~13.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bsdtar-debuginfo", rpm:"bsdtar-debuginfo~3.1.2~13.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-debugsource", rpm:"libarchive-debugsource~3.1.2~13.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive-devel", rpm:"libarchive-devel~3.1.2~13.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13", rpm:"libarchive13~3.1.2~13.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13-debuginfo", rpm:"libarchive13-debuginfo~3.1.2~13.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13-32bit", rpm:"libarchive13-32bit~3.1.2~13.2", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libarchive13-debuginfo-32bit", rpm:"libarchive13-debuginfo-32bit~3.1.2~13.2", rls:"openSUSELeap42.1"))) {
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
