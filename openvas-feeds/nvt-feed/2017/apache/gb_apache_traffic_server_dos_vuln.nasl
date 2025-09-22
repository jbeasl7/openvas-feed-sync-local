# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:traffic_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812229");
  script_version("2023-08-11T05:05:41+0000");
  script_cve_id("CVE-2015-3249");
  script_tag(name:"last_modification", value:"2023-08-11 05:05:41 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2017-11-29 16:59:37 +0530 (Wed, 29 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-18 16:17:00 +0000 (Sat, 18 Nov 2017)");
  script_name("Apache Traffic Server (ATS) 5.3.x < 5.3.1 DoS Vulnerability");

  script_tag(name:"summary", value:"Apache Traffic Server is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in 'frame_handlers array' and
  'set_dynamic_table_size function'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial of service (out-of-bounds access and daemon crash) or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"Apache Traffic Server version 5.3.x before 5.3.1.");

  script_tag(name:"solution", value:"Update to version 5.3.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("gb_apache_traffic_server_http_detect.nasl");
  script_mandatory_keys("apache/ats/detected");
  script_xref(name:"URL", value:"https://yahoo-security.tumblr.com/post/122883273670/apache-traffic-server-http2-fuzzing");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version =~ "^5\.3" && version_is_less(version: version, test_version: "5.3.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.3.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
