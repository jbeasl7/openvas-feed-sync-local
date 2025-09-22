# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:dedecms:dedecms";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170257");
  script_version("2023-12-01T16:11:30+0000");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-12-01 15:11:58 +0000 (Thu, 01 Dec 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-22 18:06:00 +0000 (Tue, 22 Nov 2022)");

  script_cve_id("CVE-2022-43192");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DedeCMS V5.7 SP2 <= 5.7.107 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_dedecms_http_detect.nasl");
  script_mandatory_keys("dedecms/detected");

  script_tag(name:"summary", value:"DedeCMS is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An arbitrary file upload vulnerability in the component
  /dede/file_manage_control.php allows attackers to execute arbitrary code via a crafted PHP file.");

  script_tag(name:"affected", value:"DedeCMS V5.7 SP2 through version 5.7.107.");

  script_tag(name:"solution", value:"Update to version 5.7.108 or later.");

  script_xref(name:"URL", value:"https://github.com/linchuzhu/Dedecms-v5.7.101-RCE");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version =~ "^5" ) {
  if ( version_is_less_equal( version:version, test_version:"5.7.107" ) ) {
    report = report_fixed_ver( installed_version:version, fixed_version:"5.7.108", install_path:location );
    security_message( port:port, data:report );
    exit( 0 );
  }
} else {
  exit( 99 );
}

exit( 99 );
