# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:kentico:kentico";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113366");
  script_version("2025-03-25T05:38:56+0000");
  script_tag(name:"last_modification", value:"2025-03-25 05:38:56 +0000 (Tue, 25 Mar 2025)");
  script_tag(name:"creation_date", value:"2019-04-03 10:44:31 +0000 (Wed, 03 Apr 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-16 17:54:02 +0000 (Tue, 16 Jul 2024)");

  script_cve_id("CVE-2019-10068");

  # nb: In the CISA KEV so don't "hide" behind a too low QoD. See solution tag to create an override
  # instead.
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Kentico CMS <= 12.0.14 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_kentico_cms_http_detect.nasl");
  script_mandatory_keys("kentico/cms/detected");

  script_tag(name:"summary", value:"Kentico CMS is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Due to a failure to validate security headers, it's possible
  for a specially crafted request to the staging service to bypass initial authentication and
  proceed to deserialize user-controlled .NET object input. This deserialization then leads to
  unauthenticated remote code execution on the server where the Kentico instance is hosted.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute
  arbitrary code on the target system.");

  script_tag(name:"affected", value:"Kentico CMS prior to version 12.0.15.

  This vulnerability only exists if the Staging Service authentication is not set to X.509.");

  script_tag(name:"solution", value:"Update to version 12.0.15 or later.

  Note: Please create an override for this result if the hotfix has been applied.");

  script_xref(name:"URL", value:"https://devnet.kentico.com/download/hotfixes#securityBugs-v12");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "12.0.15" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "12.0.15", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
