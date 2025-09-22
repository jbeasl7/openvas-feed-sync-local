# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:tenable:nessus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108098");
  script_version("2023-11-17T16:10:13+0000");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-11-17 16:10:13 +0000 (Fri, 17 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-03-14 13:00:00 +0100 (Tue, 14 Mar 2017)");

  script_cve_id("CVE-2017-6543");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tenable Nessus < 6.10.2 Arbitrary File Upload Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_tenable_nessus_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("tenable/nessus/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"Tenable Nessus is prone to an arbitrary file upload
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A remote, authenticated attacker may leverage this issue to
  upload arbitrary files to the affected host. This can result in arbitrary code execution within
  the context of the vulnerable application.");

  script_tag(name:"affected", value:"Tenable Nessus versions 6.8.0, 6.8.1, 6.9.0 to 6.9.3, 6.10.0,
  6.10.1 running on a windows host.");

  script_tag(name:"solution", value:"Update to version 6.10.2 or later.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96418");
  script_xref(name:"URL", value:"https://www.tenable.com/security/tns-2017-06");

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

if( version_in_range( version:vers, test_version:"6.8.0", test_version2:"6.10.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"6.10.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
