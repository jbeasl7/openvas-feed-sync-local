# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:traffic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805128");
  script_version("2023-08-11T05:05:41+0000");
  script_cve_id("CVE-2014-10022");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2015-01-21 11:00:56 +0530 (Wed, 21 Jan 2015)");
  script_name("Apache Traffic Server HTTP TRACE Request Remote DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_apache_traffic_server_http_detect.nasl");
  script_mandatory_keys("apache/ats/detected");

  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/TS-3223");
  script_xref(name:"URL", value:"http://mail-archives.apache.org/mod_mbox/trafficserver-users/201412.mbox/thread");

  script_tag(name:"summary", value:"Apache Traffic Server is prone to a remote denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to an improper handling HTTP
  TRACE requests with a 'Max-Forwards' header value of '0'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to crash the traffic_manager process.");

  script_tag(name:"affected", value:"Apache Traffic Server version 5.1.x
  before 5.1.2");

  script_tag(name:"solution", value:"Upgrade to version 5.1.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers =~ "^5\.1"){
  if(version_in_range(version:vers, test_version:"5.1.0", test_version2:"5.1.1")){
    report = 'Installed version: ' + vers + '\n' + 'Fixed version: 5.1.2 \n';
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
