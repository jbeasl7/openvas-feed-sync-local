# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811041");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2017-7989", "CVE-2017-7987", "CVE-2017-7984");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-03 13:05:00 +0000 (Wed, 03 May 2017)");
  script_tag(name:"creation_date", value:"2017-05-15 13:21:09 +0530 (Mon, 15 May 2017)");
  script_name("Joomla! 'swf' File Upload And Multiple Cross-Site Scripting Vulnerabilities");

  script_tag(name:"summary", value:"Joomla is prone to swf file upload and multiple cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Inadequate mime type checks.

  - Inadequate escaping of file and folder names.

  - Inadequate filtering.");

  script_tag(name:"impact", value:"Successfully exploiting these issues allow
  remote attackers to upload swf files even if they were explicitly forbidden
  and conduct cross-site scripting attacks.");

  script_tag(name:"affected", value:"Joomla core versions 3.2.0 through 3.6.5");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.7.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/687-core-xss-vulnerability.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98021");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98018");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/689-20170407-core-acl-violations");
  script_xref(name:"URL", value:"https://developer.joomla.org/security-centre/684-20170402-core-xss-vulnerability");

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

if(jVer =~ "^(3\.)")
{
  if(version_in_range(version:jVer, test_version:"3.2.0", test_version2:"3.6.5"))
  {
    report = report_fixed_ver( installed_version:jVer, fixed_version:"3.7.0");
    security_message( data:report, port:jPort);
    exit(0);
  }
}

exit(0);
