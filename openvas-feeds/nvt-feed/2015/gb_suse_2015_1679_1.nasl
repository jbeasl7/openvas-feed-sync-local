# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.850692");
  script_version("2022-07-05T11:37:00+0000");
  script_tag(name:"last_modification", value:"2022-07-05 11:37:00 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"creation_date", value:"2015-10-06 12:41:13 +0200 (Tue, 06 Oct 2015)");
  script_cve_id("CVE-2015-4500", "CVE-2015-4505", "CVE-2015-4506", "CVE-2015-4509", "CVE-2015-4511", "CVE-2015-4517", "CVE-2015-4519", "CVE-2015-4520", "CVE-2015-4521", "CVE-2015-4522", "CVE-2015-7174", "CVE-2015-7175", "CVE-2015-7176", "CVE-2015-7177", "CVE-2015-7178", "CVE-2015-7179", "CVE-2015-7180");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("openSUSE: Security Advisory for MozillaThunderbird (openSUSE-SU-2015:1679-1)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'MozillaThunderbird'
  package(s) announced via the referenced advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"MozillaThunderbird was updated to fix 17 security issues.

  These security issues were fixed:

  - CVE-2015-4509: Use-after-free vulnerability in the HTMLVideoElement
  interface in Mozilla Firefox before 41.0 and Firefox ESR 38.x before
  38.3 allowed remote attackers to execute arbitrary code via crafted
  JavaScript code that modifies the URI table of a media element, aka
  ZDI-CAN-3176 (bsc#947003).

  - CVE-2015-4520: Mozilla Firefox before 41.0 and Firefox ESR 38.x before
  38.3 allowed remote attackers to bypass CORS preflight protection
  mechanisms by leveraging (1) duplicate cache-key generation or (2)
  retrieval of a value from an incorrect HTTP Access-Control-* response
  header (bsc#947003).

  - CVE-2015-4521: The ConvertDialogOptions function in Mozilla Firefox
  before 41.0 and Firefox ESR 38.x before 38.3 might allowed remote
  attackers to cause a denial of service (memory corruption and
  application crash) or possibly have unspecified other impact via unknown
  vectors (bsc#947003).

  - CVE-2015-4522: The nsUnicodeToUTF8::GetMaxLength function in Mozilla
  Firefox before 41.0 and Firefox ESR 38.x before 38.3 might allowed
  remote attackers to cause a denial of service (memory corruption and
  application crash) or possibly have unspecified other impact via unknown
  vectors, related to an 'overflow (bsc#947003).

  - CVE-2015-4500: Multiple unspecified vulnerabilities in the browser
  engine in Mozilla Firefox before 41.0 and Firefox ESR 38.x before 38.3
  allowed remote attackers to cause a denial of service (memory corruption
  and application crash) or possibly execute arbitrary code via unknown
  vectors (bsc#947003).

  - CVE-2015-4511: Heap-based buffer overflow in the
  nestegg_track_codec_data function in Mozilla Firefox before 41.0 and
  Firefox ESR 38.x before 38.3 allowed remote attackers to execute
  arbitrary code via a crafted header in a WebM video (bsc#947003).

  - CVE-2015-7178: The ProgramBinary::linkAttributes function in libGLES in
  ANGLE, as used in Mozilla Firefox before 41.0 and Firefox ESR 38.x
  before 38.3 on Windows, mishandles shader access, which allowed remote
  attackers to execute arbitrary code or cause a denial of service (memory
  corruption and application crash) via crafted (1) OpenGL or (2) WebGL
  content (bsc#947003).

  - CVE-2015-7179: The VertexBufferInterface::reserveVertexSpace function in
  libGLES in ANGLE, as used in Mozilla Firefox before 41.0 and Firefox ESR
  38.x before 38.3 on Windows, incorrectly allocates memory for shader
  attribute arrays, which allowed remote attackers to execute arbitra ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"MozillaThunderbird on openSUSE 13.2, openSUSE 13.1");

  script_tag(name:"solution", value:"Please install the updated package(s).");
  script_xref(name:"openSUSE-SU", value:"2015:1679-1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSE13\.2|openSUSE13\.1)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSE13.2") {
  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~38.3.0~28.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~38.3.0~28.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~38.3.0~28.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~38.3.0~28.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~38.3.0~28.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~38.3.0~28.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~38.3.0~28.1", rls:"openSUSE13.2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSE13.1") {
  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird", rpm:"MozillaThunderbird~38.3.0~70.65.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-buildsymbols", rpm:"MozillaThunderbird-buildsymbols~38.3.0~70.65.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debuginfo", rpm:"MozillaThunderbird-debuginfo~38.3.0~70.65.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-debugsource", rpm:"MozillaThunderbird-debugsource~38.3.0~70.65.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-devel", rpm:"MozillaThunderbird-devel~38.3.0~70.65.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-common", rpm:"MozillaThunderbird-translations-common~38.3.0~70.65.1", rls:"openSUSE13.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"MozillaThunderbird-translations-other", rpm:"MozillaThunderbird-translations-other~38.3.0~70.65.1", rls:"openSUSE13.1"))) {
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
