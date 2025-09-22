# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.802252");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2011-0552", "CVE-2011-0553", "CVE-2011-0554");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-10-18 15:48:35 +0200 (Tue, 18 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Symantec IM Manager <= 8.4.17 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_symantec_prdts_detect.nasl");
  script_mandatory_keys("Symantec/IM/Manager");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  script code in the browser, compromise the application, access or modify data, or exploit latent
  vulnerability in the underlying database.");

  script_tag(name:"affected", value:"Symantec IM Manager versions 8.4.17 and prior.");

  script_tag(name:"insight", value:"- Input passed to the 'refreshRateSetting' parameter in
  IMManager/Admin/IMAdminSystemDashboard.asp, 'nav' and 'menuitem' parameters in
  IMManager/Admin/IMAdminTOC_simple.asp, and 'action' parameter in
  IMManager/Admin/IMAdminEdituser.asp is not properly sanitised before being returned to the user.
  This can be exploited to execute arbitrary HTML and script code in a user's browser session in
  the context of an affected site.

  - Input validation errors exist within the Administrator Console allows remote attackers to
  execute arbitrary code or SQL commands via unspecified vectors.");

  script_tag(name:"solution", value:"Update to version 8.4.18 (build 8.4.1405) or later.");

  script_tag(name:"summary", value:"Symantec IM Manager is prone to multiple vulnerabilities.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/43157");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49738");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49739");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49742");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1026130");
  script_xref(name:"URL", value:"http://www.symantec.com/business/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2011&suid=20110929_00");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("Symantec/IM/Manager"))
  exit(0);

if(version_is_less(version:vers, test_version:"8.4.1405")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"8.4.18 (build 8.4.1405)");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);