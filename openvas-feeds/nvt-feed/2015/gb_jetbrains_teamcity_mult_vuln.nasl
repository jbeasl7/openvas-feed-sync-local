# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805444");
  script_version("2024-03-06T05:05:53+0000");
  script_cve_id("CVE-2014-10036", "CVE-2014-10002");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-03-06 05:05:53 +0000 (Wed, 06 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-04-07 10:25:40 +0530 (Tue, 07 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("JetBrains TeamCity < 8.1 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"JetBrains Teamcity is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends a crafted request via HTTP GET and
  checks whether the software is installed with the vulnerable version or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The feed/generateFeedUrl.html script does not validate input to the
  'cameFromUrl' parameter before returning it to users.

  - An unspecified error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to create a specially crafted request that would execute arbitrary
  script code in a user's browser session and gain access to potentially
  sensitive information.");

  script_tag(name:"affected", value:"JetBrains TeamCity version before 8.1");

  script_tag(name:"solution", value:"Upgrade to JetBrains TeamCity 8.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.netsparker.com/critical-xss-vulnerabilities-in-teamcity/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jetbrains_teamcity_http_detect.nasl");
  script_mandatory_keys("jetbrains/teamcity/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

CPE = "cpe:/a:jetbrains:teamcity";

if(!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if(isnull(version = get_app_version(cpe: CPE, port: port)))
  exit(0);

if(version_is_less(version: version, test_version: "8.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.1");
  security_message(data: report, port: port);
  exit(0);
}
