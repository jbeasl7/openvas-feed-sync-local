# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.90010");
  script_version("2022-07-06T10:11:12+0000");
  script_tag(name:"last_modification", value:"2022-07-06 10:11:12 +0000 (Wed, 06 Jul 2022)");
  script_tag(name:"creation_date", value:"2008-05-15 23:18:24 +0200 (Thu, 15 May 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-0043");
  script_name("Microsoft .NET JIT Compiler Code Execution Vulnerability (ms07-040)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/registry_enumerated");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2007/Jul/1018356.html");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2007/ms07-040");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/24811");

  script_tag(name:"summary", value:"Microsoft .NET JIT Compiler is prone to a code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if System.web.dll version is less than 2.0.50727.832.");

  script_tag(name:"impact", value:"The Just In Time (JIT) Compiler service in Microsoft .NET
  Framework 1.0, 1.1, and 2.0 for Windows 2000, XP, Server 2003, and Vista allows user-assisted
  remote attackers to execute arbitrary code via unspecified vectors involving an unchecked buffer,
  probably a buffer overflow, aka .NET JIT Compiler Vulnerability.");

  script_tag(name:"affected", value:"- Microsoft .NET Framework 1.1 SP 1

  - Microsoft .NET Framework 1.0 SP 3

  - Microsoft .NET Framework 2.0 SP 1/SP 2");

  script_tag(name:"solution", value:"All Users should upgrade to the latest version. Please see the
  references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("http_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win2008:3) <= 0){
  exit(0);
}

# MS07-040 Hotfix check
if((hotfix_missing(name:"928367") == 0)|| (hotfix_missing(name:"928366") == 0)||
   (hotfix_missing(name:"933854") == 0)|| (hotfix_missing(name:"929729") == 0)||
   (hotfix_missing(name:"929916") == 0)){
    exit(0);
}

key  = "SOFTWARE\Microsoft\Windows\CurrentVersion\SharedDlls\";
foreach item (registry_enum_values(key:key))
{
  if("System.Web.dll" >< item)
  {
    path = item;
    break;
  }
}

if(!path){
  exit(0);
}

if("c:" >< path){
  path =  ereg_replace(pattern:"c:", replace:"C:", string:path);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:path);
dllVer = GetVer(file:file, share:share);

if(!dllVer){
  exit(0);
}

if(version_in_range(version:dllVer, test_version:"1.0", test_version2:"1.0.3705.6059")||
   version_in_range(version:dllVer, test_version:"1.1", test_version2:"1.1.4322.2406")||
   version_in_range(version:dllVer, test_version:"2.0", test_version2:"2.0.50727.831")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    path =  path + "\system.web.dll";
    share = ereg_replace(pattern:"([a-zA-Z]):.*", replace:"\1$", string:path);
    file = ereg_replace(pattern:"[a-zA-Z]:(.*)", replace:"\1", string:path);

    dllVer = GetVer(file:file, share:share);
    if(!dllVer){
      exit(0);
    }
  }
}

if(hotfix_check_sp(winVista:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"1.0",test_version2:"1.0.3705.6059")||
     version_in_range(version:dllVer, test_version:"1.1", test_version2:"1.1.4322.2406")||
     version_in_range(version:dllVer, test_version:"2.0", test_version2:"2.0.50727.831"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
     }
}

if(hotfix_check_sp(win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"1.0",test_version2:"1.0.3705.6059")||
     version_in_range(version:dllVer, test_version:"1.1", test_version2:"1.1.4322.2406"))
     {
       security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
     }
}

