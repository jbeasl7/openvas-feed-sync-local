# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:centreon:centreon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807337");
  script_version("2025-01-31T05:37:27+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-31 05:37:27 +0000 (Fri, 31 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-06-07 16:34:49 +0530 (Tue, 07 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Centreon 'POST' Parameter Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Centreon is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An insufficient validation of user supplied input via post parameter
    'img_comment' to 'main.php' script.

  - An improper verification of uploaded files via the 'filename' POST
    parameter.

  - The validity checks are not performed to verify the HTTP requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to perform certain actions with administrative privileges, to execute
  arbitrary code into user's browser session on the affected site.");

  script_tag(name:"affected", value:"Centreon version 2.6.1");

  script_tag(name:"solution", value:"Upgrade to Centreon 2.6.3 or 2.7 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/38339");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_centreon_web_http_detect.nasl");
  script_mandatory_keys("centreon_web/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if (version_is_equal(version:version, test_version:"2.6.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"2.6.3 or 2.7 or later");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
