# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:atlassian:jira";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100740");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-08-03 13:36:27 +0200 (Tue, 03 Aug 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Jira Cross Site Scripting and Information Disclosure Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_atlassian_jira_http_detect.nasl");
  script_mandatory_keys("atlassian/jira/detected");

  script_tag(name:"summary", value:"Atlassian JIRA is prone to multiple cross-site scripting vulnerabilities
  and an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The application fails to sufficiently sanitize user-supplied input.");

  script_tag(name:"impact", value:"Attackers can exploit these issues to obtain sensitive information,
  steal cookie-based authentication information, and execute arbitrary client-side scripts in the context of
  the browser.");

  script_tag(name:"affected", value:"Jira 4.01 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"Update to the latest JIRA version.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42025");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if("#" >< version) {
  jver = split(version, sep: "#", keep: FALSE);
  if(!isnull(jver[0])) {
    version = jver[0];
  }
}

if (version_is_less_equal(version: version, test_version: "4.0.1")) {
   report = report_fixed_ver(installed_version:version, vulnerable_range:"Less or equal to 4.0.1");
   security_message(port: port, data: report);
   exit(0);
}

exit(0);
