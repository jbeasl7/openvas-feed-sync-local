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
  script_oid("1.3.6.1.4.1.25623.1.0.852478");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2018-14779", "CVE-2018-14780");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-02-25 04:15:00 +0000 (Tue, 25 Feb 2020)");
  script_tag(name:"creation_date", value:"2019-05-09 02:00:46 +0000 (Thu, 09 May 2019)");
  script_name("openSUSE: Security Advisory for yubico-piv-tool (openSUSE-SU-2019:1341-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"openSUSE-SU", value:"2019:1341-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-05/msg00016.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'yubico-piv-tool'
  package(s) announced via the openSUSE-SU-2019:1341-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for yubico-piv-tool fixes the following issues:

  Security issues fixed:

  - Fixed a buffer overflow and an out of bounds memory read in
  ykpiv_transfer_data(), which could be triggered by a malicious token.
  (CVE-2018-14779, bsc#1104809, YSA-2018-03)

  - Fixed a buffer overflow and an out of bounds memory read in
  _ykpiv_fetch_object(), which could be triggered by a malicious token.
  (CVE-2018-14780, bsc#1104811, YSA-2018-03)

  This update was imported from the SUSE:SLE-15:Update update project.

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-1341=1");

  script_tag(name:"affected", value:"'yubico-piv-tool' package(s) on openSUSE Leap 15.0.");

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

  if(!isnull(res = isrpmvuln(pkg:"libykcs11-1", rpm:"libykcs11-1~1.5.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libykcs11-1-debuginfo", rpm:"libykcs11-1-debuginfo~1.5.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libykcs11-devel", rpm:"libykcs11-devel~1.5.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libykpiv-devel", rpm:"libykpiv-devel~1.5.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libykpiv1", rpm:"libykpiv1~1.5.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libykpiv1-debuginfo", rpm:"libykpiv1-debuginfo~1.5.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yubico-piv-tool", rpm:"yubico-piv-tool~1.5.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yubico-piv-tool-debuginfo", rpm:"yubico-piv-tool-debuginfo~1.5.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"yubico-piv-tool-debugsource", rpm:"yubico-piv-tool-debugsource~1.5.0~lp150.2.3.1", rls:"openSUSELeap15.0"))) {
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
