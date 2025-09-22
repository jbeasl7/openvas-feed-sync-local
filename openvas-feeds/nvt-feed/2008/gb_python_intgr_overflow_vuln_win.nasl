# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800056");
  script_version("2024-02-15T05:05:39+0000");
  script_cve_id("CVE-2008-5031");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2008-11-14 10:43:16 +0100 (Fri, 14 Nov 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Python Multiple Integer Overflow Vulnerabilities - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://exchange.xforce.ibmcloud.com/vulnerabilities/46612");

  script_tag(name:"impact", value:"Remote exploitation will allow execution of arbitrary code
  via large number of integer values to modules.");

  script_tag(name:"affected", value:"Python 2.5.2.");

  script_tag(name:"insight", value:"The flaw exists due the way it handles large integer values
  in the tabsize arguments as input to expandtabs methods (string_expandtabs and nicode_expandtabs)
  in stringobject.c and unicodeobject.c.");

  script_tag(name:"solution", value:"Update to Python 2.5.5 or later.");

  script_tag(name:"summary", value:"Python is prone to an integer overflow vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"2.5.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.5.5", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );