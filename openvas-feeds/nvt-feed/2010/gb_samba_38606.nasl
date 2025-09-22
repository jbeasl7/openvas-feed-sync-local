# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100522");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"creation_date", value:"2010-03-09 22:32:06 +0100 (Tue, 09 Mar 2010)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0728");
  script_name("Samba 'CAP_DAC_OVERRIDE' File Permissions Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38606");
  script_xref(name:"URL", value:"https://bugzilla.samba.org/show_bug.cgi?id=7222");
  script_xref(name:"URL", value:"http://us1.samba.org/samba/security/CVE-2010-0728.html");

  script_tag(name:"summary", value:"Samba is prone to a vulnerability that may allow attackers to bypass
  certain security restrictions.");

  script_tag(name:"impact", value:"Successful exploits may allow attackers to gain unauthorized write and
  read access to files.");

  script_tag(name:"affected", value:"This issue affects Samba versions 3.3.11, 3.4.6 and 3.5.0. Versions
  3.4.5 and prior and 3.3.10 and prior are not affected.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

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

if( version_is_equal( version:vers, test_version:"3.3.11" ) ||
    version_is_equal( version:vers, test_version:"3.4.6" ) ||
    version_is_equal( version:vers, test_version:"3.5.0" ) ||
    version_in_range( version:vers, test_version:"3.4", test_version2:"3.4.5" ) ||
    version_in_range( version:vers, test_version:"3.3", test_version2:"3.3.10" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:loc );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
