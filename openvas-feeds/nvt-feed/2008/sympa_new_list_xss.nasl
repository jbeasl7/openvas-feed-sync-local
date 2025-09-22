# SPDX-FileCopyrightText: 2008 Tenable Network Security
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sympa:sympa";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80090");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2004-1735");
  script_xref(name:"OSVDB", value:"9081");
  script_xref(name:"Secunia", value:"12339");

  script_name("Sympa < 4.1.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Tenable Network Security");
  script_family("Web application abuses");
  script_dependencies("sympa_detect.nasl");
  script_mandatory_keys("sympa/detected");

  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/2004-08/0293.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10992");

  script_tag(name:"solution", value:"Update to version 4.1.3 or newer.");

  script_tag(name:"summary", value:"The remote web server contains a CGI script that is affected by a
  cross-site scripting vulnerability.");

  script_tag(name:"impact", value:"The flaw may allow a user who has the privileges to create a new list
  to inject HTML tags in the list description field.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

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

if (version_is_less(version: version, test_version: "4.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
