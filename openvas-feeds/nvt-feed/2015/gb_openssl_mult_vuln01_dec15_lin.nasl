# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806654");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2015-3193", "CVE-2015-1794");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-19 11:14:00 +0000 (Fri, 19 Aug 2022)");
  script_tag(name:"creation_date", value:"2015-12-18 08:55:30 +0530 (Fri, 18 Dec 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSL Multiple Vulnerabilities -01 (Dec 2015) - Linux");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in the montgomery squaring implementation within the
  crypto/bn/asm/x86_64-mont5.pl script.

  - An error in the ssl3_get_key_exchange function in ssl/s3_clnt.c script.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to conduct denial of service attack and gain access to potentially
  sensitive information.");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.2 before 1.0.2e on
  Linux");

  script_tag(name:"solution", value:"Upgrade to OpenSSL 1.0.2e or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://openssl.org/news/secadv/20151203.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

if(vers =~ "^1\.0\.2" && version_is_less(version:vers, test_version:"1.0.2e")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.0.2e", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
