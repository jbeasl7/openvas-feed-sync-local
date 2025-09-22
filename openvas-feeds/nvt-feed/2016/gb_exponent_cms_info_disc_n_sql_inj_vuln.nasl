# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:exponentcms:exponent_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809728");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-9284", "CVE-2016-9285", "CVE-2016-9282", "CVE-2016-9283",
                "CVE-2016-9242", "CVE-2016-9183", "CVE-2016-9184", "CVE-2016-9182",
                "CVE-2016-9481");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-28 01:29:00 +0000 (Fri, 28 Jul 2017)");
  script_tag(name:"creation_date", value:"2016-11-17 13:31:19 +0530 (Thu, 17 Nov 2016)");
  script_name("Exponent CMS <= 2.4.0 Information Disclosure and SQLi Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_exponet_cms_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ExponentCMS/installed");

  script_xref(name:"URL", value:"https://github.com/exponentcms/exponent-cms/releases/tag/v2.4.0patch1");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94296");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94194");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94227");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94227");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94590");
  script_xref(name:"URL", value:"https://github.com/exponentcms/exponent-cms/releases/tag/v2.4.0patch2");

  script_tag(name:"summary", value:"Exponent CMS is prone to an SQL injection (SQLi) and an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in 'getUsersByJSON' of the framework/modules/users/controllers/usersController.php
  script.

  - An error in the framework/modules/addressbook/controllers/addressController.php script while
  passing input via modified id number.

  - An input passed via 'search_string' parameter to the
  framework/modules/search/controllers/searchController.php script is not validated properly.

  - An error in the framework/core/subsystems/expRouter.php script allowing to read database
  information via address/addContentToSearch/id/ and a trailing string.

  - Input passed via 'content_type' and 'subtype' parameter to the
  framework/modules/core/controllers/expRatingController.php script is not validated properly.

  - Insufficient sanitization of input passed via 'selectObjectsBySql' to the
  /framework/modules/ecommerce/controllers/orderController.php script.

  - Insufficient validation of input passed to the
  /framework/modules/core/controllers/expHTMLEditorController.php script.

  - Exponent CMS permits undefined actions to execute by default.

  - Input passed via 'content_id' parameter into showComments within the
  framework/modules/core/controllers/expCommentController.php script is not sanitized properly.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain
  access to potentially sensitive information and execute arbitrary SQL commands.");

  script_tag(name:"affected", value:"Exponent CMS version 2.4.0 and prior.");

  script_tag(name:"solution", value:"Update to the latest release version.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

vtstrings = get_vt_strings();

url = dir + "/users/getUsersByJSON/sort/" + vtstrings["default"] + "test";

if( http_vuln_check( port:port, url:url, check_header:TRUE,
                     pattern:'admin","password":"[a-zA-Z0-9]',
                     extra_check:make_list( 'content="Exponent Content Management System',
                                            "lastname", "firstname", "email", "recordsReturned" ) ) ) {
  report = http_report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );