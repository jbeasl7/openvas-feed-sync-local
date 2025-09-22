# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:portswigger:burp_suite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813614");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-1153");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-08-14 13:43:00 +0000 (Tue, 14 Aug 2018)");
  script_tag(name:"creation_date", value:"2018-06-19 16:08:53 +0530 (Tue, 19 Jun 2018)");
  script_name("Burp Suite CE 1.7.32 - 1.7.33 MITM Vulnerability - Linux");

  script_tag(name:"summary", value:"Burp Suite Community Edition is prone to a man-in-the-middle
  (MITM) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to Burp sends a couple of HTTPS requests without
  verifying the server certificate.");

  script_tag(name:"impact", value:"Successful exploitation will allow a man in the middle to
  intercept communication and inject new data.");

  script_tag(name:"affected", value:"Burp Suite Community Edition 1.7.32 and 1.7.33.");

  script_tag(name:"solution", value:"Update to version 1.7.34 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"http://releases.portswigger.net/2018/06/1734.html");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_burp_suite_ce_detect_lin.nasl");
  script_mandatory_keys("BurpSuite/CE/Linux/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"1.7.32", test_version2:"1.7.33")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.7.34", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);