# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:elastic:logstash";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808095");
  script_version("2025-09-03T14:11:39+0000");
  script_cve_id("CVE-2014-4326");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-09-03 14:11:39 +0000 (Wed, 03 Sep 2025)");
  script_tag(name:"creation_date", value:"2016-06-24 17:58:32 +0530 (Fri, 24 Jun 2016)");
  script_name("Elastic Logstash 'CVE-2014-4326' RCE Vulnerability");

  script_tag(name:"summary", value:"Elastic Logstash is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Flaw is due improper validation of
  inputs passed to 'zabbix.rb' and 'nagios_nsca.rb' outputs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  remote attackers to execute arbitrary commands.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"affected", value:"Elastic Logstash version prior to
  1.4.2.");

  script_tag(name:"solution", value:"Update to Elastic Logstash version
  1.4.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.elastic.co/community/security/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/532841/100/0/threaded");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_elastic_logstash_consolidation.nasl");
  script_mandatory_keys("elastic/logstash/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(esPort = get_app_port(cpe:CPE))){
 exit(0);
}

if(!esVer = get_app_version(cpe:CPE, port:esPort)){
 exit(0);
}

if(version_is_less(version:esVer, test_version:"1.4.2"))
{
  report = report_fixed_ver(installed_version:esVer, fixed_version:"1.4.2");
  security_message(data:report, port:esPort);
  exit(0);
}

