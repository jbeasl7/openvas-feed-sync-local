# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cybozu:garoon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113401");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2019-05-29 14:15:01 +0000 (Wed, 29 May 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-5945", "CVE-2019-5946");

  script_name("Cybozu Garoon >= 4.2.4, <= 4.10.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cybozu_products_http_detect.nasl");
  script_mandatory_keys("cybozu/garoon/detected");

  script_tag(name:"summary", value:"Cybozu Garoon is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Remote attackers may obtain obtain user credentials via the authentication mechanism

  - An open redirect vulnerability allows remote attackers to redirect users to arbitrary web sites
  and conduct phishing attacks via the Login Screen");

  script_tag(name:"affected", value:"Cybozu Garoon versions 4.2.4 through 4.10.1.");

  script_tag(name:"solution", value:"Update to version 4.10.2 or later.");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN58849431/index.html");
  script_xref(name:"URL", value:"https://kb.cybozu.support/article/35488/");
  script_xref(name:"URL", value:"https://kb.cybozu.support/article/35492/");

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

if(version_in_range(version:version, test_version:"4.2.4", test_version2:"4.10.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"4.10.2", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
