# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127366");
  script_version("2025-04-11T15:45:04+0000");
  script_tag(name:"last_modification", value:"2025-04-11 15:45:04 +0000 (Fri, 11 Apr 2025)");
  script_tag(name:"creation_date", value:"2023-03-17 06:28:22 +0000 (Fri, 17 Mar 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-23 21:02:00 +0000 (Thu, 23 Mar 2023)");

  script_cve_id("CVE-2023-23935", "CVE-2023-28107", "CVE-2023-28111", "CVE-2023-28112",
                "CVE-2023-25819", "CVE-2023-30606");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 3.1.x < 3.1.0.beta3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_http_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2023-23935: Presence of restricted personal messages may be leaked if tagged with a tag

  - CVE-2023-28107: Multisite DoS by spamming backups

  - CVE-2023-28111: SSRF protection bypass possible with IPv4-mapped IPv6 addresses

  - CVE-2023-28112: SSRF protection missing for some FastImage requests

  - CVE-2023-25819: Tags that are normally private are showing in metadata

  - CVE-2023-30606: Multisite DoS through unsanitized dynamic dispatch to SiteSetting");

  script_tag(name:"affected", value:"Discourse versions 3.1.x prior to 3.1.0.beta3.");

  script_tag(name:"solution", value:"Update to version 3.1.0.beta3 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-rf8j-mf8c-82v7");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-cp7c-fm4c-6xxx");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-26h3-8ww8-v5fc");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-9897-x229-55gh");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-xx2h-mwm7-hq6q");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-jj93-w3mv-3jvv");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos[ "version" ];
location = infos[ "location" ];

if( version_in_range_exclusive( version: version, test_version_lo: "3.1.0.beta", test_version_up: "3.1.0.beta3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.0.beta3", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
