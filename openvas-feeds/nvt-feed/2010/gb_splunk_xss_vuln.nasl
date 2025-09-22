# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:splunk:splunk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801226");
  script_version("2025-09-05T15:40:40+0000");
  script_tag(name:"last_modification", value:"2025-09-05 15:40:40 +0000 (Fri, 05 Sep 2025)");
  script_tag(name:"creation_date", value:"2010-07-12 09:42:32 +0200 (Mon, 12 Jul 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2010-2429");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Splunk 4.0 - 4.1.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_http_detect.nasl");
  script_mandatory_keys("splunk/detected");

  script_tag(name:"summary", value:"Splunk is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied
  input passed via the 'Referer' header before being returned to the user within a HTTP 404 error
  message when using Internet Explorer.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute
  arbitrary web script or HTML in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"Splunk version 4.0 through 4.1.2.");

  script_tag(name:"solution", value:"Update to version 4.1.3 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/40187");
  script_xref(name:"URL", value:"http://www.splunk.com/view/SP-CAAAFHY");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/59517");

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

if (version_in_range(version: version, test_version: "4.0", test_version2:"4.1.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
