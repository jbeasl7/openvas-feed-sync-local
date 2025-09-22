# SPDX-FileCopyrightText: 2004 David Maciejak
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15394");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11216");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11281");
  script_cve_id("CVE-2004-0815");
  script_name("Samba < 2.2.11, 3.x < 3.0.7 Remote Arbitrary File Access Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2004 David Maciejak");
  script_family("Remote file access");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_tag(name:"insight", value:"An attacker needs a valid account to exploit this flaw.");

  script_tag(name:"solution", value:"Upgrade to Samba 2.2.11 or 3.0.7.");

  script_tag(name:"summary", value:"The remote Samba server, according to its version number, is vulnerable
  to a remote file access vulnerability.");

  script_tag(name:"impact", value:"This vulnerability allows an attacker to access arbitrary files which exist
  outside of the shares's defined path.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
loc = infos["location"];

if( version_in_range( version:vers, test_version:"2.2.0", test_version2:"2.2.10" ) ||
    version_in_range( version:vers, test_version:"3.0.0", test_version2:"3.0.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.2.11/3.0.7", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
