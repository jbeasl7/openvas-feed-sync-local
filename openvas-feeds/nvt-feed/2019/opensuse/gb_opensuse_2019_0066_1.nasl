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
  script_oid("1.3.6.1.4.1.25623.1.0.852246");
  script_version("2025-02-28T05:38:49+0000");
  script_cve_id("CVE-2017-5852", "CVE-2017-5853", "CVE-2017-5854", "CVE-2017-5855",
                "CVE-2017-5886", "CVE-2017-6840", "CVE-2017-6844", "CVE-2017-6845",
                "CVE-2017-6847", "CVE-2017-7378", "CVE-2017-7379", "CVE-2017-7380",
                "CVE-2017-7994", "CVE-2017-8054", "CVE-2017-8787", "CVE-2018-5295",
                "CVE-2018-5296", "CVE-2018-5308", "CVE-2018-5309", "CVE-2018-8001");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-02-28 05:38:49 +0000 (Fri, 28 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-01-19 04:01:15 +0100 (Sat, 19 Jan 2019)");
  script_name("openSUSE: Security Advisory for podofo (openSUSE-SU-2019:0066-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/opensuse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"openSUSE-SU", value:"2019:0066-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-security-announce/2019-01/msg00027.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'podofo'
  package(s) announced via the openSUSE-SU-2019:0066-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for podofo version 0.9.6 fixes the following issues:

  Security issues fixed:

  - CVE-2017-5852: Fix an infinite loop in
  PoDoFo::PdfPage::GetInheritedKeyFromObject (PdfPage.cpp) (boo#1023067)

  - CVE-2017-5854: Fix a NULL pointer dereference in PdfOutputStream.cpp
  (boo#1023070)

  - CVE-2017-5886: Fix a heap-based buffer overflow in
  PoDoFo::PdfTokenizer::GetNextToken (PdfTokenizer.cpp) (boo#1023380)

  - CVE-2017-6844: Fix a buffer overflow in
  PoDoFo::PdfParser::ReadXRefSubsection (PdfParser.cpp) (boo#1027782)

  - CVE-2017-6847: Fix a NULL pointer dereference in
  PoDoFo::PdfVariant::DelayedLoad (PdfVariant.h) (boo#1027778)

  - CVE-2017-7379: Fix a heap-based buffer overflow in
  PoDoFo::PdfSimpleEncoding::ConvertToEncoding (PdfEncoding.cpp)
  (boo#1032018)

  - CVE-2018-5296: Fix a denial of service in the ReadXRefSubsection
  function (boo#1075021)

  - CVE-2018-5309: Fix an integer overflow in the ReadObjectsFromStream
  function (boo#1075322)

  - CVE-2017-5853: Fix a signed integer overflow in PdfParser.cpp
  (boo#1023069)

  - CVE-2017-5855: Fix a NULL pointer dereference in the ReadXRefSubsection
  function (boo#1023071)

  - CVE-2017-6840: Fix an invalid memory read in the GetColorFromStack
  function (boo#1027787)

  - CVE-2017-6845: Fix a NULL pointer dereference in the
  SetNonStrokingColorSpace function (boo#1027779)

  - CVE-2017-7378: Fix a heap-based buffer overflow in the ExpandTabs
  function (boo#1032017)

  - CVE-2017-7380: Fix four null pointer dereferences (boo#1032019)

  - CVE-2017-8054: Fix a denial of service in the GetPageNodeFromArray
  function (boo#1035596)

  - CVE-2018-5295: Fix an integer overflow in the ParseStream function
  (boo#1075026)

  - CVE-2018-5308: Fix undefined behavior in the
  PdfMemoryOutputStream::Write function (boo#1075772)

  - CVE-2018-8001: Fix a heap overflow read vulnerability in the
  UnescapeName function (boo#1084894)

  - CVE-2017-7994, CVE-2017-8787: Fix a denial of service via a crafted PDF
  document (boo#1035534, boo#1037739)

  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-66=1");

  script_tag(name:"affected", value:"podofo on openSUSE Leap 42.3.");

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
  if(!isnull(res = isrpmvuln(pkg:"libpodofo-devel", rpm:"libpodofo-devel~0.9.6~10.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0_9_6", rpm:"libpodofo0_9_6~0.9.6~10.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpodofo0_9_6-debuginfo", rpm:"libpodofo0_9_6-debuginfo~0.9.6~10.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo", rpm:"podofo~0.9.6~10.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo-debuginfo", rpm:"podofo-debuginfo~0.9.6~10.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"podofo-debugsource", rpm:"podofo-debugsource~0.9.6~10.3.1", rls:"openSUSELeap42.3"))) {
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
