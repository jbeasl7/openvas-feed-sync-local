# Copyright (C) 2012 E-Soft Inc.
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
  script_oid("1.3.6.1.4.1.25623.1.0.71292");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-3045", "CVE-2011-3049", "CVE-2011-3050", "CVE-2011-3051", "CVE-2011-3052", "CVE-2011-3053", "CVE-2011-3054", "CVE-2011-3055", "CVE-2011-3056", "CVE-2011-3057");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2012-04-30 07:59:26 -0400 (Mon, 30 Apr 2012)");
  script_name("FreeBSD Ports: chromium");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 E-Soft Inc.");
  script_family("FreeBSD Local Security Checks");

  script_tag(name:"insight", value:"The following package is affected: chromium

CVE-2011-3045
Integer signedness error in pngrutil.c in libpng before 1.4.10beta01,
as used in Google Chrome before 17.0.963.83 and other products, allows
remote attackers to cause a denial of service (application crash) or
possibly execute arbitrary code via a crafted PNG file, a different
vulnerability than CVE-2011-3026.
CVE-2011-3049
Google Chrome before 17.0.963.83 does not properly restrict the
extension web request API, which allows remote attackers to cause a
denial of service (disrupted system requests) via a crafted extension.
CVE-2011-3050
Use-after-free vulnerability in the Cascading Style Sheets (CSS)
implementation in Google Chrome before 17.0.963.83 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors related to the :first-letter pseudo-element.
CVE-2011-3051
Use-after-free vulnerability in the Cascading Style Sheets (CSS)
implementation in Google Chrome before 17.0.963.83 allows remote
attackers to cause a denial of service or possibly have unspecified
other impact via vectors related to the cross-fade function.
CVE-2011-3052
The WebGL implementation in Google Chrome before 17.0.963.83 does not
properly handle CANVAS elements, which allows remote attackers to
cause a denial of service (memory corruption) or possibly have
unspecified other impact via unknown vectors.
CVE-2011-3053
Use-after-free vulnerability in Google Chrome before 17.0.963.83
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors related to block splitting.
CVE-2011-3054
The WebUI privilege implementation in Google Chrome before 17.0.963.83
does not properly perform isolation, which allows remote attackers to
bypass intended access restrictions via unspecified vectors.
CVE-2011-3055
The browser native UI in Google Chrome before 17.0.963.83 does not
require user confirmation before an unpacked extension installation,
which allows user-assisted remote attackers to have an unspecified
impact via a crafted extension.
CVE-2011-3056
Google Chrome before 17.0.963.83 allows remote attackers to bypass the
Same Origin Policy via vectors involving a 'magic iframe.'
CVE-2011-3057
Google V8, as used in Google Chrome before 17.0.963.83, allows remote
attackers to cause a denial of service via vectors that trigger an
invalid read operation.

This VT has been deprecated and is therefore no longer functional.");

  script_tag(name:"solution", value:"Update your system with the appropriate patches or
  software upgrades.");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/search/label/Stable%20updates");
  script_xref(name:"URL", value:"http://www.vuxml.org/freebsd/330106da-7406-11e1-a1d7-00262d5ed8ee.html");

  script_tag(name:"summary", value:"The remote host is missing an update to the system
  as announced in the referenced advisory.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
