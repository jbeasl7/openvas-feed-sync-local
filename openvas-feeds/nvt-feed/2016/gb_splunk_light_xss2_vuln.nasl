# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:splunk:light";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106269");
  script_version("2024-06-26T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-06-26 05:05:39 +0000 (Wed, 26 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-09-19 11:58:34 +0700 (Mon, 19 Sep 2016)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Splunk Light 6.3.x < 6.3.5 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_light_detect.nasl");
  script_mandatory_keys("SplunkLight/installed");

  script_tag(name:"summary", value:"Splunk Light is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Splunk Light is affected by an XSS vulnerability in the Splunk
  Web.");

  script_tag(name:"impact", value:"An arbitrary script may be executed on the user's web browser.");

  script_tag(name:"affected", value:"Splunk Light versions 6.3.x.");

  script_tag(name:"solution", value:"Update to version 6.3.5 or later.");

  script_xref(name:"URL", value:"https://www.splunk.com/view/SP-CAAAPN9");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^6\.3") {
  if (version_is_less(version: version, test_version: "6.3.5")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "6.3.5");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
