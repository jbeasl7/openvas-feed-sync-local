# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:pydio:pydio";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113404");
  script_version("2025-05-01T05:40:03+0000");
  script_tag(name:"last_modification", value:"2025-05-01 05:40:03 +0000 (Thu, 01 May 2025)");
  script_tag(name:"creation_date", value:"2019-06-03 11:55:43 +0000 (Mon, 03 Jun 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_cve_id("CVE-2019-10045", "CVE-2019-10047", "CVE-2019-10048", "CVE-2019-10049");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Pydio Core <= 8.2.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_pydio_http_detect.nasl");
  script_mandatory_keys("pydio/detected");

  script_tag(name:"summary", value:"Pydio Core is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - The action 'get_sess_id' in the web application of Pydio discloses the session cookie value in
  the response body, enabling scripts to get access to its value. This identifier can be reused by
  an attacker to impersonate a user and perform actions on their behalf, if the session is still
  active.

  - A stored XSS vulnerability can be exploited by leveraging the file upload and file preview
  features of the application. An authenticated attacker can upload an HTML file containing
  JavaScript code and afterwards a file preview URL can be used to access the uploaded file. If a
  malicious user shares an uploaded HTML file containing JavaScript code with another user of the
  application and tricks them into accessing the URL that will result in the HTML code being
  interpreted by the web browser and the included JavaScript code ebeing executed under the context
  of the victim.

  - The ImageMagick plugin that is installed by default in Pydio does not perform appropriate
  validation and sanitization of user supplied input in the plugin's configuration options,
  allowing arbitrary shell commands to be entered that result in command execution on the
  underlying operating system with the privileges of the local user running the web server. The
  attacker must be authenticated into the application with an administrator account in order to be
  able to edit the affected plugin configuration.

  - Using the aforementioned XSS vulnerability against an administrator would allow an attacker to
  gain elevated privileges.

  - An issue was discovered in proxy.php. Through an unauthenticated request, it is possible to
  evaluate malicious PHP code by placing it in the fourth line of a .php file, with execution via a
  HTTP GET request to proxy.php?hash=../../../../../var/lib/pydio/data/personal/guest/[filename].
  This is related to plugins/action.share/src/Store/ShareStore.php.");

  script_tag(name:"affected", value:"Pydio Core version 8.2.2 and prior.");
  script_tag(name:"solution", value:"Update to version 8.2.3 or later.");

  script_xref(name:"URL", value:"https://www.secureauth.com/labs/advisories/pydio-8-multiple-vulnerabilities");

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

if( version_is_less( version: version, test_version: "8.2.3" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "8.2.3", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
