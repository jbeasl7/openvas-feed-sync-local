# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:piwigo:piwigo";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.131080");
  script_version("2024-11-29T15:40:53+0000");
  script_tag(name:"last_modification", value:"2024-11-29 15:40:53 +0000 (Fri, 29 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-10-25 08:51:16 +0000 (Fri, 25 Oct 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2024-46605", "CVE-2024-46606", "CVE-2024-48311", "CVE-2024-52701");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Piwigo <= 14.5.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_piwigo_detect.nasl");
  script_mandatory_keys("piwigo/installed");

  script_tag(name:"summary", value:"Piwigo is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-46605: Description field at '/admin.php' (Albums -> Manage -> Edit album ->
  Description) contains a stored XSS. It allows to perform a CSRF attack and change the email
  address of everyone who views the album.

  - CVE-2024-46606: Description field at '/admin.php' (Photos -> Recent photos -> Edit photo ->
  Description) contains a stored XSS. It allows to perform a CSRF attack and change the email
  address of everyone who views the photo.

  - CVE-2024-48311: CSRF via Edit album function.

  - CVE-2024-52701: A stored cross-site scripting (XSS) vulnerability in the Configuration page");

  script_tag(name:"affected", value:"Piwigo version 14.5.0 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 29th November, 2024.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/achufistov/cve-achufistov/blob/main/CVE-2024-46605.md");
  script_xref(name:"URL", value:"https://github.com/achufistov/cve-achufistov/blob/main/CVE-2024-46606.md");
  script_xref(name:"URL", value:"https://github.com/whiteshark2k/Piwigo-CSRF/blob/main/Piwigo-CSRF.md");
  script_xref(name:"URL", value:"https://github.com/Piwigo/Piwigo/issues/2261");

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

if( version_is_less_equal( version: version, test_version: "14.5.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 0 );
