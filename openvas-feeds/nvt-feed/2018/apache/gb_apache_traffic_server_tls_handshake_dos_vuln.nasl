# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:traffic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812524");
  script_version("2023-08-11T05:05:41+0000");
  script_cve_id("CVE-2017-7671");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-02-28 11:37:03 +0530 (Wed, 28 Feb 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-23 14:39:00 +0000 (Fri, 23 Mar 2018)");
  script_name("Apache Traffic Server (ATS) TLS Handshake DOS Vulnerability");

  script_tag(name:"summary", value:"Apache Traffic Server is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in TLS
  handshake.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service.");

  script_tag(name:"affected", value:"Apache Traffic Server 5.2.0 to 5.3.2,

  Apache Traffic Server 6.0.0 to 6.2.0 and

  Apache Traffic Server 7.0.0");

  script_tag(name:"solution", value:"5.x users upgrade to 7.1.2 or later versions,

  6.x users upgrade to 6.2.2 or later versions and

  7.x users upgrade to 7.1.2 or later versions.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2018/q1/197");
  script_xref(name:"URL", value:"https://github.com/apache/trafficserver/pull/1941");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("gb_apache_traffic_server_http_detect.nasl");
  script_mandatory_keys("apache/ats/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers == "7.0.0") {
  fix = "7.1.2";
}

else if(vers =~ "^5\.2") {
  if(version_in_range(version:vers, test_version: "5.2", test_version2: "5.3.2")) {
    fix =  "7.1.2";
  }
}

else if(vers =~ "^6\.0") {
  if(version_in_range(version:vers, test_version: "6.0", test_version2: "6.2.0")) {
    fix =  "6.2.2";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version: vers, fixed_version: fix, install_path:path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
