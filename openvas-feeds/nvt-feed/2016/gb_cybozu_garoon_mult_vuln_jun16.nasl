# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cybozu:garoon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807849");
  script_version("2024-01-10T05:05:17+0000");
  script_cve_id("CVE-2016-1190", "CVE-2016-1193", "CVE-2016-1192", "CVE-2016-1188",
                "CVE-2016-1189", "CVE-2016-1195", "CVE-2016-1196", "CVE-2016-1191",
                "CVE-2016-1197", "CVE-2016-1194");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-06-27 18:16:00 +0000 (Mon, 27 Jun 2016)");
  script_tag(name:"creation_date", value:"2016-06-29 17:46:28 +0530 (Wed, 29 Jun 2016)");
  script_name("Cybozu Garoon 3.x < 4.2.1 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Cybozu Garoon is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to bypass
  intended restrictions and obtain sensitive information.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"affected", value:"Cybozu Garoon versions 3.x and 4.x prior to 4.2.1.");

  script_tag(name:"solution", value:"Update to version 4.2.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN25765762/index.html");
  script_xref(name:"URL", value:"https://support.cybozu.com/ja-jp/article/8877");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2016/JVNDB-2016-000095.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2016/JVNDB-2016-000077.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2016/JVNDB-2016-000093.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2016/JVNDB-2016-000081.html");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_cybozu_products_http_detect.nasl");
  script_mandatory_keys("cybozu/garoon/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version:version, test_version:"3.0", test_version2:"4.2.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"4.2.1", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
