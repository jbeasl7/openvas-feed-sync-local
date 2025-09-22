# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901168");
  script_version("2025-03-05T05:38:52+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:52 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-12-09 06:36:39 +0100 (Thu, 09 Dec 2010)");
  script_cve_id("CVE-2010-3712");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Joomla! Multiple Cross-site Scripting Vulnerabilities");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/2615");
  script_xref(name:"URL", value:"http://developer.joomla.org/security/news/9-security/10-core-security/322-20101001-core-xss-vulnerabilities");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to inject arbitrary web script
or HTML via vectors involving 'multiple encoded entities'.");

  script_tag(name:"affected", value:"Joomla! versions 1.5.x before 1.5.21");

  script_tag(name:"insight", value:"The flaws are due to inadequate filtering of multiple encoded entities, which
could be exploited by attackers to cause arbitrary scripting code to be executed by the user's browser in the
security context of an affected Web site.");

  script_tag(name:"solution", value:"Upgrade to Joomla! 1.5.21 or later.");

  script_tag(name:"summary", value:"Joomla is prone to multiple Cross-site scripting vulnerabilities.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version:"1.5", test_version2: "1.5.20")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.21");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
