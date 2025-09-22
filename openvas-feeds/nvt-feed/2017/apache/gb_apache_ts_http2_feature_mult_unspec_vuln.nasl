# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:traffic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811852");
  script_version("2023-08-11T05:05:41+0000");
  script_cve_id("CVE-2015-5206", "CVE-2015-5168");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-21 18:39:00 +0000 (Thu, 21 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-10-05 13:01:42 +0530 (Thu, 05 Oct 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Traffic Server 'HTTP/2' Multiple Unspecified Vulnerabilities");

  script_tag(name:"summary", value:"Apache Traffic Server is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple unspecified
  errors in 'HTTP/2 experimental feature'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause unknown impacts on the target system.");

  script_tag(name:"affected", value:"Apache Traffic Server versions 5.3.x before 5.3.2");

  script_tag(name:"solution", value:"Upgrade to Apache Traffic Server version
  5.3.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://mail-archives.us.apache.org/mod_mbox/www-announce/201509.mbox/%3CCABF6JR2j5vesvnjbm6sDPB_zAGj3kNgzzHEpLUh6dWG6t8mC2w@mail.gmail.com%3E");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_apache_traffic_server_http_detect.nasl");
  script_mandatory_keys("apache/ats/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(vers == "5.3.0" || vers == "5.3.1") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"5.3.2");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
