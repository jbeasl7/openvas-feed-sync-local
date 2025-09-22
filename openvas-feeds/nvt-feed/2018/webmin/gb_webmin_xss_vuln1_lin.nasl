# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:webmin:webmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140650");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-01-04 13:28:09 +0700 (Thu, 04 Jan 2018)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-12 12:55:00 +0000 (Fri, 12 Jan 2018)");

  script_cve_id("CVE-2017-17089");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Webmin XSS Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("webmin.nasl", "os_detection.nasl");
  script_mandatory_keys("webmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Webmin is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"custom/run.cgi in Webmin allows remote authenticated administrators to
conduct XSS attacks via the description field in the custom command functionality.");

  script_tag(name:"affected", value:"Webmin prior to version 1.870.");

  script_tag(name:"solution", value:"Update to version 1.870 or later.");

  script_xref(name:"URL", value:"https://github.com/webmin/webmin/commit/a9c97eea6c268fb83d93a817d58bac75e0d2599e");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102339");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.870")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.870");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
