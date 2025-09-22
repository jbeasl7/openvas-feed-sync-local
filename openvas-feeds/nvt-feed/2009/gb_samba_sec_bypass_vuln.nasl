# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900685");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2009-1888");
  script_name("Samba Format String Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Remote file access");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35539");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35472");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1664");

  script_tag(name:"affected", value:"Samba 3.0.0 before 3.0.35 on Linux.

  Samba 3.1.x on Linux.

  Samba 3.2.4 before 3.2.13 on Linux.

  Samba 3.3.0 before 3.3.6 on Linux.");

  script_tag(name:"insight", value:"The flaw is due to uninitialised memory access error in 'smbd' when denying
  attempts to modify a restricted access control list. This can be exploited
  to modify the ACL of an already writable file without required permissions.");

  script_tag(name:"solution", value:"Update to version 3.3.6 or later.");

  script_tag(name:"summary", value:"Samba is prone to a security bypass vulnerability.");

  script_tag(name:"impact", value:"When dos filemode is set to yes in the smb.conf, attackers can exploit this
  issue to bypass certain security restrictions and compromise a user's system.");

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

if( version_in_range( version:vers, test_version:"3.0", test_version2:"3.0.34" ) ||
    version_in_range( version:vers, test_version:"3.2", test_version2:"3.2.12" ) ||
    version_in_range( version:vers, test_version:"3.3", test_version2:"3.3.5" ) ||
    vers =~ "^3\.1" ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.35/3.2.13/3.3.6", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
