# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800404");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-01-09 13:48:55 +0100 (Fri, 09 Jan 2009)");
  script_tag(name:"cvss_base", value:"6.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:N/A:N");
  script_cve_id("CVE-2009-0022");
  script_name("Samba 3.2.0 - 3.2.6 Root File System Access Security Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Remote file access");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/33379");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33118");
  script_xref(name:"URL", value:"http://liudieyu0.blog124.fc2.com/blog-entry-6.html");
  script_xref(name:"URL", value:"http://us1.samba.org/samba/security/CVE-2009-0022.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/497091/100/0/threaded");

  script_tag(name:"affected", value:"Samba 3.2.0 through 3.2.6 on Linux.");

  script_tag(name:"insight", value:"Access to the root file system is granted when authenticated users connect
  to a share with an empty string as name.");

  script_tag(name:"solution", value:"Update to version 3.2.7 or later.");

  script_tag(name:"summary", value:"Samba is prone to a system access security vulnerability.");

  script_tag(name:"impact", value:"Successful local exploitation could result in bypassing certain
  security restrictions by malicious users.");

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

if( version_in_range( version:vers, test_version:"3.2.0", test_version2:"3.2.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.2.7", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
