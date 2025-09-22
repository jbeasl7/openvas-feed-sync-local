# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.803092");
  script_version("2022-04-25T14:50:49+0000");
  script_cve_id("CVE-2012-6270", "CVE-2012-6271");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-01-02 13:05:18 +0530 (Wed, 02 Jan 2013)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities (Jan 2013) - Windows");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/546769");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56972");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56975");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/519137");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027903");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027905");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80712");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/80713");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to execute
  arbitrary code by tricking a user into visiting a specially crafted document.");

  script_tag(name:"affected", value:"Adobe Shockwave Player versions 11.6.8.638 and prior.");

  script_tag(name:"insight", value:"- An error in Xtras allows attackers to trigger installation of
  arbitrary signed Xtras via a Shockwave movie that contains an Xtra URL.

  - An error exists when handling a specially crafted HTML document that calls Shockwave content via
  a compatibility parameter forcing the application to downgrade to the insecure version.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"Adobe Shockwave Player is prone to multiple vulnerabilities.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");
include("smb_nt.inc");
include("secpod_activex.inc");

shockVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(!shockVer)
  exit(0);

if(version_is_less_equal(version:shockVer, test_version:"11.6.8.638"))
{
  clsids = make_list("{166B1BCA-3F9C-11CF-8075-444553540000}",
                     "{233C1507-6A77-46A4-9443-F871F945D258}");

  foreach clsid (clsids)
  {
    if(is_killbit_set(clsid:clsid) == 0)
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}
