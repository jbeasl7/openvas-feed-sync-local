# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113738");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-08-06 07:09:45 +0000 (Thu, 06 Aug 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-31 14:15:00 +0000 (Fri, 31 Jul 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-15801");

  script_name("Python <= 3.8.4 Arbitrary Code Execution Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("General");
  script_dependencies("gb_python_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("python/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Python is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerability exists because sys.path restrictions
  specified in a python38._pth file are ignored, allowing code to be loaded from arbitrary
  locations.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute
  arbitrary code on the target machine.");

  script_tag(name:"affected", value:"Python through version 3.8.4.");

  script_tag(name:"solution", value:"Update to version 3.8.5 or later.");

  script_xref(name:"URL", value:"https://bugs.python.org/issue41304");
  script_xref(name:"URL", value:"https://github.com/python/cpython/pull/21495");

  exit(0);
}

CPE = "cpe:/a:python:python";

include( "host_details.inc" );
include( "version_func.inc" );

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE, version_regex: "^[0-9]+\.[0-9]+\.[0-9]+" ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "3.8.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.8.5", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
