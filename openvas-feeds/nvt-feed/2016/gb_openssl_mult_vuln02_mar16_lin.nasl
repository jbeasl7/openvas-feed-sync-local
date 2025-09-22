# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807500");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2016-0703", "CVE-2016-0704");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-18 18:18:00 +0000 (Thu, 18 Jan 2018)");
  script_tag(name:"creation_date", value:"2016-03-03 12:23:09 +0530 (Thu, 03 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSL Multiple Vulnerabilities -02 (Mar 2016) - Linux");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - The SSLv2 servers using OpenSSL accepted SSLv2 connection handshakes that
    indicated non-zero clear key length for non-export cipher suites.

  - The SSLv2 protocol implementation in OpenSSL did not properly implement the
    Bleichenbacher protection for export cipher suites.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to decrypt TLS ciphertext data and to obtain sensitive information.");

  script_tag(name:"affected", value:"OpenSSL versions before 0.9.8zf, 1.0.0
  before 1.0.0r, 1.0.1 before 1.0.1m, and 1.0.2 before 1.0.2a.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL 1.0.2a or 1.0.1m or
  1.0.0r or 0.9.8zf or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20160301.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

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

if(vers =~ "^1\.0\.0") {
  if(version_is_less(version:vers, test_version:"1.0.0r")) {
    fix = "1.0.0r";
    VULN = TRUE;
  }
}
else if(vers =~ "^1\.0\.1") {
  if(version_is_less(version:vers, test_version:"1.0.1m")) {
    fix = "1.0.1m";
    VULN = TRUE;
  }
}
else if(vers =~ "^1\.0\.2") {
  if(version_is_less(version:vers, test_version:"1.0.2a")) {
    fix = "1.0.2a";
    VULN = TRUE;
  }
}
else if(vers =~ "^0\.[0-9]+") {
  version = eregmatch(pattern:"([0-9.]+)([a-z])?([a-z])?", string:vers);
  if(version[1] && version[2] && version[3])
    vers = version[1] + "." + version[2] + "." + version[3];
  else if(version[0])
    vers = version[0];

  if(version_is_less(version:vers, test_version:"0.9.8.z.f")) {
    fix = "0.9.8zf";
    VULN = TRUE;
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
