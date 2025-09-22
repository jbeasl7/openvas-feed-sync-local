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
  script_oid("1.3.6.1.4.1.25623.1.0.851691");
  script_version("2025-02-28T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"creation_date", value:"2018-01-29 07:46:42 +0100 (Mon, 29 Jan 2018)");
  script_cve_id("CVE-2017-11423", "CVE-2017-12374", "CVE-2017-12375", "CVE-2017-12376",
                "CVE-2017-12377", "CVE-2017-12378", "CVE-2017-12379", "CVE-2017-12380",
                "CVE-2017-6418", "CVE-2017-6419", "CVE-2017-6420");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for clamav (openSUSE-SU-2018:0258-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'clamav'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for clamav fixes the following issues:

  - Update to security release 0.99.3 (bsc#1077732)

  * CVE-2017-12376 (ClamAV Buffer Overflow in handle_pdfname Vulnerability)

  * CVE-2017-12377 (ClamAV Mew Packet Heap Overflow Vulnerability)

  * CVE-2017-12379 (ClamAV Buffer Overflow in messageAddArgument
  Vulnerability)

  - these vulnerabilities could have allowed an unauthenticated, remote
  attacker to cause a denial of service (DoS) condition
  or potentially execute arbitrary code on an affected device.

  * CVE-2017-12374 (ClamAV use-after-free Vulnerabilities)

  * CVE-2017-12375 (ClamAV Buffer Overflow Vulnerability)

  * CVE-2017-12378 (ClamAV Buffer Over Read Vulnerability)

  * CVE-2017-12380 (ClamAV Null Dereference Vulnerability)

  - these vulnerabilities could have allowed an unauthenticated, remote
  attacker to cause a denial of service (DoS) condition on an affected
  device.

  * CVE-2017-6420 (bsc#1052448)

  - this vulnerability could have allowed remote attackers to cause a
  denial of service (use-after-free) via a crafted PE file with WWPack
  compression.

  * CVE-2017-6419 (bsc#1052449)

  - ClamAV could have allowed remote attackers to cause a denial of
  service (heap-based buffer overflow and application crash) or
  possibly have unspecified other impact via a crafted CHM file.

  * CVE-2017-11423 (bsc#1049423)

  - ClamAV could have allowed remote attackers to cause a denial of
  service (stack-based buffer over-read and application crash) via a
  crafted CAB file.

  * CVE-2017-6418 (bsc#1052466)

  - ClamAV could have allowed remote attackers to cause a denial
  of service (out-of-bounds read) via a crafted e-mail message.

  - update upstream keys in the keyring

  - provide and obsolete clamav-nodb to trigger it's removal in Leap
  bsc#1040662

  This update was imported from the SUSE:SLE-12:Update update project.");

  script_tag(name:"affected", value:"clamav on openSUSE Leap 42.3");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_xref(name:"openSUSE-SU", value:"2018:0258-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2018-01/msg00078.html");
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
  if(!isnull(res = isrpmvuln(pkg:"clamav", rpm:"clamav~0.99.3~20.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debuginfo", rpm:"clamav-debuginfo~0.99.3~20.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"clamav-debugsource", rpm:"clamav-debugsource~0.99.3~20.1", rls:"openSUSELeap42.3"))) {
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
