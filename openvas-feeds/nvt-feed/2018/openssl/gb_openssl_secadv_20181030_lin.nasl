# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112411");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2018-0734");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 20:41:00 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"creation_date", value:"2018-11-01 10:16:23 +0100 (Thu, 01 Nov 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSL: Timing vulnerability in DSA signature generation (CVE-2018-0734) - Linux");

  script_tag(name:"summary", value:"OpenSSL is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The OpenSSL DSA signature algorithm has been shown to be vulnerable to a
  timing side channel attack. An attacker could use variations in the signing
  algorithm to recover the private key.");

  script_tag(name:"affected", value:"OpenSSL versions 1.1.0-1.1.0i, 1.1.1 and 1.0.2-1.0.2p.");

  script_tag(name:"solution", value:"Upgrade OpenSSL to version 1.1.0j-dev, 1.1.1a-dev, 1.0.2q-dev or manually apply the fixes via Github.
  See the references for more details.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20181030.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/105758");
  script_xref(name:"URL", value:"https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=43e6a58d4991a451daf4891ff05a48735df871ac");
  script_xref(name:"URL", value:"https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=8abfe72e8c1de1b95f50aa0d9134803b4d00070f");
  script_xref(name:"URL", value:"https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=ef11e19d1365eea2b1851e6f540a0bf365d303e7");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  exit(0);
}

CPE = "cpe:/a:openssl:openssl";

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"1.1.0", test_version2:"1.1.0i")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.1.0j-dev", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_is_equal(version:vers, test_version:"1.1.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.1.1a-dev", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

if(version_in_range(version:vers, test_version:"1.0.2", test_version2:"1.0.2p")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.2q-dev", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
