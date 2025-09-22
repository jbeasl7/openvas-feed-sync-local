# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902535");
  script_version("2024-01-22T05:07:31+0000");
  script_tag(name:"last_modification", value:"2024-01-22 05:07:31 +0000 (Mon, 22 Jan 2024)");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_cve_id("CVE-2011-1333");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Cybozu Products Images XSS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cybozu_products_http_detect.nasl");
  script_mandatory_keys("cybozu/products/detected");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45063");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48446");
  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN80877328/index.html");
  script_xref(name:"URL", value:"http://jvndb.jvn.jp/en/contents/2011/JVNDB-2011-000045.html");

  script_tag(name:"summary", value:"Cybozu Office or Cybozu Garoon is prone to a cross-site
  scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of unspecified input
  related to downloading images from the bulletin board, which allows attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute
  arbitrary HTML and script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"- Cybozu Office versions 6.x

  - Cybozu Garoon versions 2.0.0 through 2.1.3");

  script_tag(name:"solution", value:"Update to:

  - Cybozu Garoon version 2.5.0 or later

  - Cybozu Office version 7 or later");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:cybozu:office",
                     "cpe:/a:cybozu:garoon");

if(!infos = get_app_port_from_list(cpe_list:cpe_list))
  exit(0);

port = infos["port"];
cpe = infos["cpe"];

if(!infos = get_app_version_and_location(cpe:cpe, port:port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(cpe == "cpe:/a:cybozu:office") {
  if(version =~ "^6\.+") {
    report = report_fixed_ver(installed_version:version, fixed_version:"7", install_path:location);
    security_message(port:port, data:report);
    exit(0);
  }
}

else if(cpe == "cpe:/a:cybozu:garoon") {
  if(version_in_range(version:version, test_version:"2.0.0", test_version2:"2.1.3")) {
    report = report_fixed_ver(installed_version:version, fixed_version:"2.5.0", install_path:location);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);
