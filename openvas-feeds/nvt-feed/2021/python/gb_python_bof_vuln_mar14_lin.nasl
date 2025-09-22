# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:python:python";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118261");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2021-11-01 11:45:13 +0100 (Mon, 01 Nov 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2014-1912");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Python 'socket.recvfrom_into' Buffer Overflow Vulnerability (Mar 2014) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://bugs.python.org/issue20246");
  script_xref(name:"URL", value:"http://secunia.com/advisories/56624");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31875");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1029831");

  script_tag(name:"summary", value:"Python is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a boundary error within the
  'sock_recvfrom_into' function.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to
  cause a buffer overflow, resulting in a denial of service or potentially allowing the
  execution of arbitrary code.");

  script_tag(name:"affected", value:"Python version 2.5 before 2.7.7 and 3.x before 3.3.4.");

  script_tag(name:"solution", value:"Update to Python version 2.7.7, 3.3.4 or later.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE, version_regex:"^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version:version, test_version:"2.5.0", test_version2:"2.7.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"2.7.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.0", test_version2:"3.3.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.3.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
