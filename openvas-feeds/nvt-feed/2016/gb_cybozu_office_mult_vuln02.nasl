# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cybozu:office";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807277");
  script_version("2024-01-10T05:05:17+0000");
  script_cve_id("CVE-2016-1150", "CVE-2016-1149", "CVE-2015-7798", "CVE-2015-7797",
                "CVE-2015-7796", "CVE-2015-7795", "CVE-2015-8487");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-01-10 05:05:17 +0000 (Wed, 10 Jan 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-02-22 22:31:00 +0000 (Mon, 22 Feb 2016)");
  script_tag(name:"creation_date", value:"2016-03-03 18:23:43 +0530 (Thu, 03 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cybozuo Office 9.0.0 - 10.3.0 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Cybozu Office is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in multiple functions.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause an
  information disclosure or arbitrary script may be executed on the user's web browser.");

  script_tag(name:"affected", value:"Cybozu Office versions 9.0.0 through 10.3.0.");

  script_tag(name:"solution", value:"Update to version 10.4.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN47296923/index.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83286");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/83289");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN69278491/index.html");

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

if(version_in_range(version:version, test_version:"9.0.0", test_version2:"10.3.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"10.4.0", install_path:location);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
