# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cybozu:dezie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807423");
  script_version("2024-01-10T05:05:17+0000");
  script_cve_id("CVE-2014-5314");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2016-03-03 18:23:54 +0530 (Thu, 03 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cybozu Dezie <= 8.1.0 Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"Cybozu Dezie is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified buffer overflow
  vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a
  denial-of-service, or execute arbitrary code.");

  script_tag(name:"affected", value:"Cybozu Dezie version 8.1.0 and prior.");

  script_tag(name:"solution", value:"Update to version 8.1.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN14691234/index.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71057");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cybozu_products_http_detect.nasl");
  script_mandatory_keys("cybozu/dezie/detected");

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

if(version_is_less(version:version, test_version:"8.1.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.1.1", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
