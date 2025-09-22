# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:eclipse:jetty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800954");
  script_version("2024-06-11T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-06-11 05:05:40 +0000 (Tue, 11 Jun 2024)");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2009-3579");

  script_name("Jetty 'CookieDump.java' Cross-Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.coresecurity.com/content/jetty-persistent-xss");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/507013/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_jetty_http_detect.nasl");
  script_mandatory_keys("jetty/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary code
  and conduct XSS attacks via a direct GET request to cookie/.");

  script_tag(name:"affected", value:"Jetty version 6.1.19 and 6.1.20.");

  script_tag(name:"insight", value:"The user supplied data passed into the 'Value' parameter in the Sample
  Cookies aka 'CookieDump.java' application is not adequately sanitised before being returned to the user.");

  script_tag(name:"solution", value:"Upgrade to version 6.1.21 or 7.0.0 or later.");

  script_tag(name:"summary", value:"Jetty WebServer is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if (version_is_equal(version: vers, test_version: "6.1.19")||
    version_is_equal(version: vers, test_version: "6.1.20")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "6.1.21", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
