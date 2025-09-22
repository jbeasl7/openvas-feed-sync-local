# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mahara:mahara";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801889");
  script_version("2025-08-26T05:39:52+0000");
  script_tag(name:"last_modification", value:"2025-08-26 05:39:52 +0000 (Tue, 26 Aug 2025)");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2011-1402", "CVE-2011-1403", "CVE-2011-1404", "CVE-2011-1405",
                "CVE-2011-1406");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Mahara < 1.3.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mahara_http_detect.nasl");
  script_mandatory_keys("mahara/detected");

  script_tag(name:"summary", value:"Mahara is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - An error in artefact/plans/viewtasks.json.php, artefact/blog/posts.json.php, and
  blocktype/myfriends/myfriends.json.php when checking a user's permission can be exploited to
  access restricted views.

  - An error in view/newviewtoken.json.php, artefact/plans/tasks.json.php, and
  artefact/blog/view/index.json.php when checking a user's permission can be exploited to edit
  restricted views.

  - An error in admin/users/search.json.php due to the 'INSTITUTIONALADMIN' permission not being
  checked can be exploited to search and suspend other users.

  - The application allows users to perform certain actions via HTTP requests without performing
  any validity checks to verify the requests. This can be exploited to create an arbitrary user
  with administrative privileges if a logged-in administrative user visits a malicious web site.

  - Input passed via certain email fields as a result of forum posts and view feedback
  notifications is not properly sanitised in artefact/comment/lib.php and
  interaction/forum/lib.php before being used.

  - Improper handling of an https URL in the wwwroot configuration setting, allows user-assisted
  remote attackers to obtain credentials by sniffing the network at a time when an http URL is used
  for a login.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary script code in the browser of an unsuspecting user in the context of the affected site,
  steal cookie-based authentication credentials, disclose or modify sensitive information, or
  perform certain administrative actions and bypass security restrictions.");

  script_tag(name:"affected", value:"Mahara prior to version 1.3.6.");

  script_tag(name:"solution", value:"Update to version 1.3.6 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/44433");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47798");
  script_xref(name:"URL", value:"https://launchpad.net/mahara/+milestone/1.3.6");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.3.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.3.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
