# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811257");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2017-11612");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-31 12:09:00 +0000 (Mon, 31 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-07-26 11:07:10 +0530 (Wed, 26 Jul 2017)");
  script_name("Joomla! Core Cross-Site Scripting Vulnerability (Jul 2017)");

  script_tag(name:"summary", value:"Joomla is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to Inadequate filtering
  of potentially malicious HTML tags in various components of the application.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow
  remote attacker to conduct cross-site scripting attacks.");

  script_tag(name:"affected", value:"Joomla core versions 1.5.0 through 3.7.3.");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.7.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/701-20170704-core-installer-lack-of-ownership-verification");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!jPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!jVer = get_app_version(cpe:CPE, port:jPort)){
  exit(0);
}

if(version_in_range(version:jVer, test_version:"1.5.0", test_version2:"3.7.3"))
{
  report = report_fixed_ver( installed_version:jVer, fixed_version:"3.7.4");
  security_message( data:report, port:jPort);
  exit(0);
}
exit(0);
