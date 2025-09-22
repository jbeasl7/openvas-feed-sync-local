# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:oracle:glassfish_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100191");
  script_version("2024-09-25T05:06:11+0000");
  script_tag(name:"last_modification", value:"2024-09-25 05:06:11 +0000 (Wed, 25 Sep 2024)");
  script_tag(name:"creation_date", value:"2009-05-10 17:01:14 +0200 (Sun, 10 May 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2009-1553");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("GlassFish Enterprise Server <= 2.1 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_eclipse_glassfish_http_detect.nasl");
  script_mandatory_keys("eclipse/glassfish/detected");

  script_tag(name:"summary", value:"GlassFish Enterprise Server is prone to multiple cross-site
  scripting (XSS) vulnerabilities because it fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Attacker-supplied HTML and script code would run in the context
  of the affected site, potentially allowing the attacker to steal cookie-based authentication
  credentials.");

  script_tag(name:"affected", value:"GlassFish Enterprise Server version 2.1 and probably prior.");

  script_tag(name:"solution", value:"Please see the references for a solution.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34824");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"See references");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
