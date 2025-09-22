# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cybozu:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807276");
  script_version("2024-01-10T05:05:17+0000");
  script_cve_id("CVE-2016-1153", "CVE-2016-1152", "CVE-2016-1151", "CVE-2015-8489",
                "CVE-2015-8486", "CVE-2015-8485", "CVE-2015-8484");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:26:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"creation_date", value:"2016-03-03 18:23:55 +0530 (Thu, 03 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cybozu Office 9.9.0 - 10.3.0 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Cybozu Office is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An error in 'customapp' function.

  - An error in multiple functions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial-of-service, view the information about the groupware, obtain privileged information or
  cause specific functions to become unusable.");

  script_tag(name:"affected", value:"Cybozu Office version 9.9.0 through 10.3.0.");

  script_tag(name:"solution", value:"Update to version 10.4.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN20246313/index.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83288");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83287");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83284");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN48720230/index.html");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN64209269/index.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cybozu_products_http_detect.nasl");
  script_mandatory_keys("cybozu/office/detected");

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

if(version_in_range(version:version, test_version:"9.9.0", test_version2:"10.3.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"10.4.0", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
