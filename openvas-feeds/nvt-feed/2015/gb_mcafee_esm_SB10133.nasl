# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mcafee:enterprise_security_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105478");
  script_version("2025-01-21T05:37:33+0000");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2015-7310");

  script_name("McAfee Enterprise Security Manager OS Command Injection Vulnerability (SB10133)");

  script_xref(name:"URL", value:"https://web.archive.org/web/20160328220122/https://kc.mcafee.com/corporate/index?page=content&id=SB10133");

  script_tag(name:"summary", value:"McAfee Enterprise Security Manager (ESM) is prone to an OS
  command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The product includes a function to upload and download files for
  use within the ESM. A carefully crafted filename, when downloaded, can cause command execution in
  the context of the ESM web server. The attack vector requires valid authentication to the ESM to
  execute.

  This flaw is encountered if any authenticated user downloads a file with a specially crafted
  filename from the ESM.");

  script_tag(name:"affected", value:"McAfee ESM version 9.3.2MR17, 9.4.2MR7, 9.5.0MR6 and earlier.");

  script_tag(name:"solution", value:"Update to version 9.3.2MR18, 9.4.2_MR8, 9.5.0MR7, 9.5.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"2025-01-21 05:37:33 +0000 (Tue, 21 Jan 2025)");
  script_tag(name:"creation_date", value:"2015-12-04 13:38:09 +0100 (Fri, 04 Dec 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_mcafee_esm_version.nasl");
  script_mandatory_keys("mcafee/esm/version", "mcafee/esm/mr");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) )
  exit( 0 );

v = split( version, sep:"mr", keep:FALSE ); # Example: 9.5.0mr7

if( isnull( v[0] ) || isnull( v[1] ) )
  exit( 0 );

version = v[0] + "." + v[1]; # Example: 9.5.0.7

if( version_in_range( version:version, test_version:"9.3.2", test_version2:"9.3.2.17" ) )
  fix = "9.3.2MR18 / 9.5.1";
else if( version_in_range( version:version, test_version:"9.4.2", test_version2:"9.4.2.7" ) )
  fix = "9.4.2MR8 / 9.5.1";
else if( version_in_range( version:version, test_version:"9.5.0", test_version2:"9.5.0.6" ) )
  fix = "9.5.0MR7 / 9.5.1";

if( fix ) {
  report = report_fixed_ver( installed_version:v[0] + "MR" + v[1], fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
