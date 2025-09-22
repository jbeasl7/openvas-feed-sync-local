# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cmsmadesimple:cms_made_simple";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113380");
  script_version("2024-05-07T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-05-07 05:05:33 +0000 (Tue, 07 May 2024)");
  script_tag(name:"creation_date", value:"2019-04-29 12:27:28 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-05 20:47:00 +0000 (Wed, 05 Jun 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2019-11513", "CVE-2019-11226", "CVE-2019-10105", "CVE-2019-10106",
                "CVE-2019-10107", "CVE-2019-10017");

  script_name("CMS Made Simple <= 2.2.12 Multiple Reflected XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cms_made_simple_http_detect.nasl");
  script_mandatory_keys("cmsmadesimple/detected");

  script_tag(name:"summary", value:"CMS Made Simple is prone to multiple reflected cross-site
  scripting (XSS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The File Manager is prone to a reflected XSS via the 'New Name' field in a Rename action.

  - XSS Vulnerability via the m1_name parameter in 'Add Article' under Content->Content Manager->News.

  - Self-XSS Vulnerability via the Layout Design Manager 'Name' field, which is reachable via a
    'Create a new Template' action to the Designer.

  - XSS Vulnerability via the moduleinterface.php 'Name' field, which is reachable via an
  'Add Category' action to the 'Site Admin Settings - News module' section.

  - XSS Vulnerability via the myaccount.php 'Email Address' field, which is reachable via the
  'My Preferences - My Account' section.

  - XSS Vulnerability via the moduleinterface.php Name field, which is reachable via an
  'Add a new Profile' action to the File Picker.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  inject arbitrary JavaScript and HTML into the site.");

  script_tag(name:"affected", value:"CMS Made Simple through version 2.2.12.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://dev.cmsmadesimple.org/bug/view/12022");
  script_xref(name:"URL", value:"http://dev.cmsmadesimple.org/bug/view/12001");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/153071/CMS-Made-Simple-2.2.10-Cross-Site-Scripting.html");
  script_xref(name:"URL", value:"https://ctrsec.io/index.php/2019/03/24/cmsmadesimple-xss-filepicker/");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "2.2.12" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
