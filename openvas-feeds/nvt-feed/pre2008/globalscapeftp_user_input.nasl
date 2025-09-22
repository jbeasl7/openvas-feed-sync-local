# SPDX-FileCopyrightText: 2005 SensePost
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18627");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-1415");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/13454");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("GlobalSCAPE Secure FTP Server <= 3.0.2 User Input Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 SensePost");
  script_family("Gain a shell remotely");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/globalscape/secure_ftp/detected");

  script_tag(name:"summary", value:"GlobalSCAPE Secure FTP Server is prone to a buffer overflow
  vulnerability due to mishandling the user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker would first need to authenticate to the server before
  they can execute arbitrary commands.");

  script_tag(name:"affected", value:"GlobalSCAPE Secure FTP Server version 3.0.2 and prior.");

  script_tag(name:"solution", value:"Update to the latest release of this software.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);
ftpbanner = ftp_get_banner(port:port);
if ( ftpbanner && egrep(pattern:"^220 GlobalSCAPE Secure FTP Server \(v. 3(.0|\.0\.[0-2])\)",string:ftpbanner) )
  security_message(port);
