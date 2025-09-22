# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124858");
  script_version("2025-07-25T05:44:05+0000");
  script_tag(name:"last_modification", value:"2025-07-25 05:44:05 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-18 05:10:52 +0000 (Fri, 18 Jul 2025)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-06-20 17:38:28 +0000 (Fri, 20 Jun 2025)");

  script_cve_id("CVE-2025-48063");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki 16.10.0-rc-1 < 16.10.4, 17.0.0-rc-1 < 17.1.0 RCE Vulnerability (GHSA-rhfv-688c-p6hp)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Part of the security model of required rights is that a user
  who doesn't have a right also cannot define that right as required right. That way, users who are
  editing documents on which required rights are enforced can be sure that they're not giving a
  right to a script or object that it didn't have before. A bug in the implementation of the
  enforcement of this rule means that in fact, it was possible for any user with edit right on a
  document to set programming right as required right. If then a user with programming right edited
  that document, the content of that document would gain programming right, allowing remote code
  execution.");

  script_tag(name:"affected", value:"XWiki version 16.10.0-rc-1 prior to 16.10.4 and 17.0.0-rc-1
  prior to 17.1.0.");

  script_tag(name:"solution", value:"Update to version 16.10.4, 17.1.0 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-rhfv-688c-p6hp");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range_exclusive( version:version, test_version_lo:"16.10.0-rc-1", test_version_up:"16.10.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"16.10.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range_exclusive( version:version, test_version_lo:"17.0.0-rc-1", test_version_up:"17.1.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"17.1.0", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
