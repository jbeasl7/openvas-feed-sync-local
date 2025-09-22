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
  script_oid("1.3.6.1.4.1.25623.1.0.801581");
  script_version("2023-01-12T10:12:15+0000");
  script_cve_id("CVE-2011-0638");
  script_tag(name:"last_modification", value:"2023-01-12 10:12:15 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"creation_date", value:"2011-01-31 05:37:34 +0100 (Mon, 31 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows HID Functionality (Over USB) Code Execution Vulnerability (Jan 2011)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_xref(name:"URL", value:"http://www.cs.gmu.edu/~astavrou/publications.html");
  script_xref(name:"URL", value:"http://news.cnet.com/8301-27080_3-20028919-245.html");
  script_xref(name:"URL", value:"http://www.blackhat.com/html/bh-dc-11/bh-dc-11-briefings.html#Stavrou");

  script_tag(name:"summary", value:"A USB device driver software is prone to a code execution
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks via SMB if a specific device driver (hidserv.dll)
  exists on the target system.");

  script_tag(name:"impact", value:"Successful exploitation will allow user-assisted attackers to
  execute arbitrary programs via crafted USB data.");

  script_tag(name:"affected", value:"All Microsoft Windows systems with an enabled USB device driver
  and no local protection mechanism against the automatic enabling of additional Human Interface
  Device (HID).");

  script_tag(name:"insight", value:"The flaw is due to error in USB device driver (hidserv.dll),
  which does not properly warn the user before enabling additional Human Interface Device (HID)
  functionality.");

  script_tag(name:"solution", value:"No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  A workaround is to introduce device filtering on the target host to only allow trusted USB devices
  to be enabled automatically. Once this workaround is in place an overwrite for this vulnerability
  can be created to mark it as a false positive.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");

if( ! sysPath = smb_get_systemroot() )
  exit( 0 );

dllPath = sysPath + "\system32\hidserv.dll";
share   = ereg_replace( pattern:"([A-Z]):.*", replace:"\1$", string:dllPath );
file    = ereg_replace( pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath );
dllVer  = GetVer( file:file, share:share );

if( dllVer ) {
  security_message( port:0, data:"File checked for existence: " + dllPath );
  exit( 0 );
}

exit( 99 );
