# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800689");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2944");
  script_name("ikiwiki Teximg Plugin TeX Command Arbitrary File Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36516");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36181");
  script_xref(name:"URL", value:"http://ikiwiki.info/security/#index35h2");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/2475");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_ikiwiki_consolidation.nasl");
  script_mandatory_keys("ikiwiki/detected");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"impact", value:"Successful exploitation will let the remote attacker to disclose the content
  of arbitrary local files.");
  script_tag(name:"affected", value:"ikiwiki versions 2.x through 2.53.3 and 3.x through 3.1415925");
  script_tag(name:"insight", value:"The vulnerability is due to error in 'teximg' plugin. It incorrectly
  allows the usage of unsafe TeX commands.");
  script_tag(name:"solution", value:"Upgrade to ikiwiki version 3.1415926 or 2.53.4.");
  script_tag(name:"summary", value:"ikiwiki is prone to an information disclosure vulnerability.");

  exit(0);
}

CPE = "cpe:/a:ikiwiki:ikiwiki";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE)) exit(0);
if(!version = get_app_version(cpe:CPE, port:port)) exit(0);

if(version_in_range(version:version, test_version:"2.0", test_version2:"2.53.3")){
  report = report_fixed_ver(installed_version:version, fixed_version:"2.53.4");
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:version, test_version:"3.0", test_version2:"3.1415925")){
  report = report_fixed_ver(installed_version:version, fixed_version:"3.1415926");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
