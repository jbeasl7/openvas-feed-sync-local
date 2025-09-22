# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.851481");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2017-02-03 12:11:01 +0530 (Fri, 03 Feb 2017)");
  script_cve_id("CVE-2016-9634", "CVE-2016-9635", "CVE-2016-9636", "CVE-2016-9807",
                "CVE-2016-9808", "CVE-2016-9810");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for gstreamer-0_10-plugins-good (openSUSE-SU-2017:0298-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-0_10-plugins-good'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer-0_10-plugins-good fixes the following issues:

  - CVE-2016-9634: Invalid FLIC files could have caused and an out-of-bounds
  write (bsc#1012102)

  - CVE-2016-9635: Invalid FLIC files could have caused and an out-of-bounds
  write (bsc#1012103)

  - CVE-2016-9636: Prevent maliciously crafted flic files from causing
  invalid memory writes (bsc#1012104)

  - CVE-2016-9807: Prevent the reading of invalid memory in
  flx_decode_chunks, leading to DoS (bsc#1013655)

  - CVE-2016-9808: Prevent maliciously crafted flic files from causing
  invalid memory accesses (bsc#1013653)

  - CVE-2016-9810: Invalid files can be used to extraneous unreferences,
  leading to invalid memory access and DoS (bsc#1013663)");

  script_tag(name:"affected", value:"gstreamer-0_10-plugins-good on openSUSE Leap 42.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2017:0298-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.1");
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
  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugin-esd", rpm:"gstreamer-0_10-plugin-esd~0.10.31~16.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugin-esd-debuginfo", rpm:"gstreamer-0_10-plugin-esd-debuginfo~0.10.31~16.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good", rpm:"gstreamer-0_10-plugins-good~0.10.31~16.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-debuginfo", rpm:"gstreamer-0_10-plugins-good-debuginfo~0.10.31~16.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-debugsource", rpm:"gstreamer-0_10-plugins-good-debugsource~0.10.31~16.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-doc", rpm:"gstreamer-0_10-plugins-good-doc~0.10.31~16.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-extra", rpm:"gstreamer-0_10-plugins-good-extra~0.10.31~16.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-extra-debuginfo", rpm:"gstreamer-0_10-plugins-good-extra-debuginfo~0.10.31~16.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-lang", rpm:"gstreamer-0_10-plugins-good-lang~0.10.31~16.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugin-esd-32bit", rpm:"gstreamer-0_10-plugin-esd-32bit~0.10.31~16.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugin-esd-debuginfo-32bit", rpm:"gstreamer-0_10-plugin-esd-debuginfo-32bit~0.10.31~16.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-32bit", rpm:"gstreamer-0_10-plugins-good-32bit~0.10.31~16.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-debuginfo-32bit", rpm:"gstreamer-0_10-plugins-good-debuginfo-32bit~0.10.31~16.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-extra-32bit", rpm:"gstreamer-0_10-plugins-good-extra-32bit~0.10.31~16.1", rls:"openSUSELeap42.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-0_10-plugins-good-extra-debuginfo-32bit", rpm:"gstreamer-0_10-plugins-good-extra-debuginfo-32bit~0.10.31~16.1", rls:"openSUSELeap42.1"))) {
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
