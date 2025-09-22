# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809744");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2016-9836", "CVE-2016-9837");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 19:27:00 +0000 (Wed, 07 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-12-07 16:06:46 +0530 (Wed, 07 Dec 2016)");

  script_name("Joomla Alternative PHP File Extensions File Upload and Information Disclosure Vulnerabilities");

  script_tag(name:"summary", value:"Joomla is prone to file upload and information disclosure vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to:

  - An error in file scanning mechanism of 'JFilterInput::isFileSafe' function
    which does not consider alternative PHP file extensions when checking
    uploaded files for PHP content.

  - Inadequate ACL checks in the Beez3 com_content article layout override.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to gain access to potentially sensitive information and
  upload and execute files with the '.php6', '.php7', '.phtml', and '.phpt'
  extensions.");

  script_tag(name:"affected", value:"Joomla core versions 3.0.0 through 3.6.4");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.6.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://github.com/XiphosResearch/exploits/tree/master/Joomraa");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94663");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94892");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/665-20161202-core-shell-upload.html");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/666-20161203-core-information-disclosure.html");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version =~ "^3") {
  if(version_in_range(version:version, test_version:"3.0.0", test_version2:"3.6.4")) {
    report = report_fixed_ver(installed_version:version, fixed_version:"3.6.5");
    security_message(data:report, port:port);
    exit(0);
  }
}

exit(99);
