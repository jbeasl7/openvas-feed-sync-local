# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:livezilla:livezilla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812760");
  script_version("2025-09-19T05:38:25+0000");
  script_cve_id("CVE-2017-15869");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-19 05:38:25 +0000 (Fri, 19 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-29 17:07:00 +0000 (Mon, 29 Apr 2019)");
  script_tag(name:"creation_date", value:"2018-02-12 13:29:54 +0530 (Mon, 12 Feb 2018)");
  script_name("LiveZilla 'knowledgebase.php' Cross Site Scripting Vulnerability");

  script_tag(name:"summary", value:"LiveZilla is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an insufficient validation
  of user supplied input via 'search-for' parameter in 'knowledgebase.php' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject arbitrary web script or HTML via the search-for parameter.");

  script_tag(name:"affected", value:"LiveZilla versions 7.0.6.0");

  script_tag(name:"solution", value:"Upgrade to version 7.0.8.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"https://www.securityfocus.com/archive/1/archive/1/541688/100/0/threaded");
  script_xref(name:"URL", value:"https://www.pallas.com/advisories/cve-2017-15869-livezilla-xss-knowledgebase");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_livezilla_detect.nasl");
  script_mandatory_keys("LiveZilla/installed");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"https://www.livezilla.net");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!livPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:livPort, exit_no_version:TRUE)) exit(0);
livVer = infos["version"];
path = infos["location"];

if(livVer == "7.0.6.0")
{
  report = report_fixed_ver(installed_version: livVer, fixed_version: "7.0.8.9 or later", install_path:path);
  security_message(port: livPort, data: report);
  exit(0);
}
exit(0);
