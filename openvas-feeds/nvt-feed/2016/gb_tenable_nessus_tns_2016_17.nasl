# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108019");
  script_version("2023-11-17T16:10:13+0000");
  script_tag(name:"last_modification", value:"2023-11-17 16:10:13 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"creation_date", value:"2016-11-11 13:00:00 +0100 (Fri, 11 Nov 2016)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-01 14:53:00 +0000 (Wed, 01 Mar 2017)");

  script_cve_id("CVE-2016-9259");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 6.9.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tenable_nessus_consolidation.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Tenable Nessus is prone to a stored cross-site scripting (XSS)
  vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject
  arbitrary web script or HTML.");

  script_tag(name:"affected", value:"Tenable Nessus versions 6.8.0, 6.8.1, 6.8.2 and 6.9.0");

  script_tag(name:"solution", value:"Update to version 6.9.1 or later.");

  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2016-17");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
location = infos["location"];

if( version_in_range( version:vers, test_version:"6.8.0", test_version2:"6.9.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.9.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
