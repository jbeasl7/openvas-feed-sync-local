# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811719");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-3735");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2017-08-31 10:30:25 +0530 (Thu, 31 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OpenSSL 'OOB read' Security Bypass Vulnerability - Windows");

  script_tag(name:"summary", value:"OpenSSL is prone to an 'OOB read' security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as OpenSSL could do a
  one-byte buffer overread if an X.509 certificate has a malformed
  IPAddressFamily extension.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will allow
  attackers to bypass security restrictions and perform unauthorized actions,
  this may aid in launching further attacks.");

  script_tag(name:"affected", value:"OpenSSL 1.1.0x prior to 1.1.0g-dev, 1.0.2x
  prior to 1.0.2m-dev, all 1.0.1x, all 0.9.8x and all 1.0.0x versions.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL version 1.1.0g-dev or
  1.0.2m-dev or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20170828.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100515");
  script_xref(name:"URL", value:"https://www.openssl.org/news/vulnerabilities.html#y2017");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

##https://www.openssl.org/news/vulnerabilities.html#y2017
if(vers =~ "^1\.1\.0" && version_is_less_equal(version:vers, test_version:"1.1.0f")) {
  fix = "1.1.0g-dev";
}
else if(vers =~ "^1\.0\.2" && version_is_less_equal(version:vers, test_version:"1.0.2l")) {
  fix = "1.0.2m-dev";
}
else if(vers =~ "^1\.0\.1" || vers =~ "^1\.0\.0" || vers =~ "^0\.9\.8") {
  fix = "1.1.0g-dev or 1.0.2m-dev";
}

if(fix) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
