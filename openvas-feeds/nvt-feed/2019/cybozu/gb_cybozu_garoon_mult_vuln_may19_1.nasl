# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cybozu:garoon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113397");
  script_version("2024-01-10T05:05:17+0000");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"creation_date", value:"2019-05-27 15:20:18 +0000 (Mon, 27 May 2019)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-05-20 15:36:00 +0000 (Mon, 20 May 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-5928", "CVE-2019-5929", "CVE-2019-5930", "CVE-2019-5931");

  script_name("Cybozu Garron 4.x <= 4.6.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cybozu_products_http_detect.nasl");
  script_mandatory_keys("cybozu/garoon/detected");

  script_tag(name:"summary", value:"Cybozu Garoon is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Cross-Site Scripting Vulnerability that allows remote attackers to inject
    arbitrary web script or HTML via the 'Customize Item' function

  - Cross-Site Scripting Vulnerability that allows remote attacker to inject
    arbitrary web script or HTML via the application 'Memo'

  - Remote attackers may bypass access restriction to browse unauthorized
    pages via the application 'Management of Basic System'

  - Authenticated attackers may alter the information with privileges
    invoking the installer");

  script_tag(name:"affected", value:"Cybozu Garoon versions 4.0.0 through 4.6.3.");

  script_tag(name:"solution", value:"Update to version 4.10.0 or later.");

  script_xref(name:"URL", value:"https://kb.cybozu.support/article/34227/");
  script_xref(name:"URL", value:"https://kb.cybozu.support/article/34277/");
  script_xref(name:"URL", value:"https://kb.cybozu.support/article/34279/");
  script_xref(name:"URL", value:"https://kb.cybozu.support/article/34283/");

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

if(version_in_range(version:version, test_version:"4.0.0", test_version2:"4.6.3")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"4.10.0", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
