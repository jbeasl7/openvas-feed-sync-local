# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113450");
  script_version("2023-11-21T05:05:52+0000");
  script_tag(name:"last_modification", value:"2023-11-21 05:05:52 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"creation_date", value:"2019-07-29 11:23:00 +0000 (Mon, 29 Jul 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-13560", "CVE-2019-13561", "CVE-2019-13562", "CVE-2019-13563");

  script_name("D-Link DIR-655 Rev. C < 3.02B05 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_mandatory_keys("d-link/dir/detected", "d-link/dir/hw_version");

  script_tag(name:"summary", value:"D-Link DIR-655 Rev. C devices are prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The devices allow remote attackers to force a blank password via the apply_sec.cgi setup_wizard
  parameter.

  - The devices allow remote attackers to execute arbitrary commands via shell metacharacters in the
  online_firmware_check.cgi check_fw_url parameter.

  - The devices allow XSS via the /www/ping_response.cgi ping_ipaddr parameter,
  the /www/ping6_response.cgi ping6_ipaddr parameter and the /www/apply_sec.cgi
  html_response_return_page parameter.

  - The devices allow CSRF for the entire management console.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to get complete
  control over the target device.");

  script_tag(name:"affected", value:"D-Link DIR-655 Rev. C devices through version 3.02B04.");

  script_tag(name:"solution", value:"Update to version 3.02B05.");

  script_xref(name:"URL", value:"https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2019/july/the-d-link-dir-655c-from-nothing-to-rce/");
  script_xref(name:"URL", value:"ftp://ftp2.dlink.com/SECURITY_ADVISEMENTS/DIR-655/REVC/DIR-655_REVC_RELEASE_NOTES_v3.02B05_BETA03.pdf");

  exit(0);
}

CPE = "cpe:/o:dlink:dir-655_firmware";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! fw_vers = get_app_version( cpe: CPE, port: port ) )
  exit( 0 );

# e.g. C
if( ! hw_vers = get_kb_item( "d-link/dir/hw_version" ) )
  exit( 0 );

hw_vers = toupper( hw_vers );
fw_vers = toupper( fw_vers );

if( hw_vers =~ "^c" && version_is_less( version: fw_vers, test_version: "3.02B05" ) ) {
  report = report_fixed_ver( installed_version: fw_vers, fixed_version: "3.02B05", extra: "Hardware revision: " + hw_vers );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
