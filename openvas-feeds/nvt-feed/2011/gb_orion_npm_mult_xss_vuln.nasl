# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:solarwinds:orion_network_performance_monitor";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801986");
  script_version("2025-09-17T05:39:26+0000");
  script_tag(name:"last_modification", value:"2025-09-17 05:39:26 +0000 (Wed, 17 Sep 2025)");
  script_tag(name:"creation_date", value:"2011-09-20 15:38:54 +0200 (Tue, 20 Sep 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SolarWinds Orion NPM 10.1.2 SP1 Multiple XSS Vulnerabilities");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2011/Sep/107");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/105020/orionsolarwinds-xss.txt");
  script_xref(name:"URL", value:"http://www.derkeiler.com/Mailing-Lists/Full-Disclosure/2011-09/msg00144.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_solarwinds_orion_npm_consolidation.nasl");
  script_mandatory_keys("solarwinds/orion/npm/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in the context of a vulnerable
  site. This may allow an attacker to steal cookie-based authentications and launch further attacks.");

  script_tag(name:"affected", value:"SolarWinds Orion Network Performance Monitor (NPM) 10.1.2 SP1.");

  script_tag(name:"insight", value:"The flaws are due to an input validation error in
  NetPerfMon/CustomChart.aspx and NetPerfMon/MapView.aspx pages when processing the 'Title' parameter.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"summary", value:"SolarWinds Orion NPM is prone to multiple cross-site scripting
  (XSS) vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_equal(version: version, test_version: "10.1.2.SP1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
