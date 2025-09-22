# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nagios:nagios";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813262");
  script_version("2025-09-11T05:38:37+0000");
  script_cve_id("CVE-2018-13457", "CVE-2018-13458", "CVE-2018-13441");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2025-09-11 05:38:37 +0000 (Thu, 11 Sep 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-11 18:15:00 +0000 (Sat, 11 Apr 2020)");
  script_tag(name:"creation_date", value:"2018-07-13 14:55:37 +0530 (Fri, 13 Jul 2018)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Nagios Core < 4.4.2 'unix socket' Multiple Denial of Service Vulnerabilities");

  script_tag(name:"summary", value:"Nagios Core is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws exist due to error in 'qh_echo',
 'qh_core' and 'qh_help'. which allows attackers to cause a local
  denial-of-service condition.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a denial of service.");

  script_tag(name:"affected", value:"Nagios Core version 4.4.1 and earlier.");

  script_tag(name:"solution", value:"Update to version 4.4.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://gist.github.com/fakhrizulkifli/87cf1c1ad403b4d40a86d90c9c9bf7ab");
  script_xref(name:"URL", value:"https://gist.github.com/fakhrizulkifli/40f3daf52950cca6de28ebec2498ff6e");
  script_xref(name:"URL", value:"https://gist.github.com/fakhrizulkifli/8df4a174158df69ebd765f824bd736b8");
  script_xref(name:"URL", value:"https://github.com/NagiosEnterprises/nagioscore/blob/master/Changelog");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_nagios_http_detect.nasl");
  script_mandatory_keys("nagios/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:version, test_version:"4.4.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"4.4.2", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
