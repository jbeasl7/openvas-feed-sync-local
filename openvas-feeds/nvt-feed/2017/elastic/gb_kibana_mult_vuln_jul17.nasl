# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:kibana";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811414");
  script_version("2025-09-03T14:11:39+0000");
  script_cve_id("CVE-2016-1000219", "CVE-2016-1000220");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 17:07:00 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-07-03 20:40:53 +0530 (Mon, 03 Jul 2017)");
  script_name("Elastic Kibana Multiple Vulnerabilities (Jul 2017)");

  script_tag(name:"summary", value:"Elastic Kibana is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to

  - when a custom output is configured for logging in, cookies and authorization
    headers could be written to the log files.

  - An input validation error in Kibana.");

  script_tag(name:"impact", value:"Successful exploitation will lead an attacker
  to execute arbitrary JavaScript in users' browsers, also attackers can hijack
  sessions of other users.");

  script_tag(name:"affected", value:"Elastic Kibana version before 4.5.4
  and 4.1.11.");

  script_tag(name:"solution", value:"Update to Elastic Kibana version
  4.5.4 or 4.1.11 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name:"URL", value:"https://www.elastic.co/community/security");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99179");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99178");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_elastic_kibana_http_detect.nasl");
  script_mandatory_keys("elastic/kibana/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"4.1.11")) {
  fix = "4.1.11";
}

else if(version =~ "^4\.5") {
  if(version_is_less(version:version, test_version:"4.5.4")) {
    fix = "4.5.4";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
