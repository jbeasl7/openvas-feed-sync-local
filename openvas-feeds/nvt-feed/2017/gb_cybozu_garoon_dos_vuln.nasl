# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cybozu:garoon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811591");
  script_version("2024-01-10T05:05:17+0000");
  script_cve_id("CVE-2017-2254");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-30 14:44:00 +0000 (Wed, 30 Aug 2017)");
  script_tag(name:"creation_date", value:"2017-09-01 11:50:27 +0530 (Fri, 01 Sep 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cybozu Garoon 3.5.0 - 4.2.5 DoS Vulnerability");

  script_tag(name:"summary", value:"Cybozu Garoon is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an improper validation of user supplied input
  in the application menu's edit function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct a
  denial-of-service attack.");

  script_tag(name:"affected", value:"Cybozu Garoon versions 3.5.0 through 4.2.5.");

  script_tag(name:"solution", value:"Update to version 4.2.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cybozu_products_http_detect.nasl");
  script_mandatory_keys("cybozu/garoon/detected");

  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN63564682/index.html");
  script_xref(name:"URL", value:"https://cs.cybozu.co.jp/2017/006442.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"3.5.0", test_version2:"4.2.5")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"4.2.6", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
