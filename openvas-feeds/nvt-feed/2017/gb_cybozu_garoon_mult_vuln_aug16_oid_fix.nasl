# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cybozu:garoon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107165");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2017-05-11 11:54:29 +0200 (Thu, 11 May 2017)");

  script_cve_id("CVE-2016-1213", "CVE-2016-1214", "CVE-2016-1215", "CVE-2016-1216", "CVE-2016-1217",
                "CVE-2016-1218", "CVE-2016-1219", "CVE-2016-1220");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-25 16:09:00 +0000 (Tue, 25 Apr 2017)");
  script_name("Cybozu Garoon < 4.2.2 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cybozu_products_http_detect.nasl");
  script_mandatory_keys("cybozu/garoon/detected");

  script_tag(name:"summary", value:"Cybozu Garoon is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to do
  redirection, XSS, authentication bypass, SQL injection and denial-of-services attacks.");

  script_tag(name:"affected", value:"Cybozu Garoon before version 4.2.2.");

  script_tag(name:"solution", value:"Update to version 4.2.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92599");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92598");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92600");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92596");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/92601");

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

if(version_is_less(version:version, test_version:"4.2.2")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"4.2.2", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
