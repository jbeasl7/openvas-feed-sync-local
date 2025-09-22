# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107203");
  script_version("2024-02-20T14:37:13+0000");
  script_cve_id("CVE-2017-3735", "CVE-2017-3736");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 14:37:13 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)");
  script_tag(name:"creation_date", value:"2017-11-03 18:50:03 +0530 (Fri, 03 Nov 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSL Multiple Vulnerabilities (Nov 2017) - Linux");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - A carry propagating bug in the x86_64 Montgomery squaring procedure.

  - Malformed X.509 IPAddressFamily which could cause OOB read.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote attacker to recover keys
  (private or secret keys) or to cause a buffer overread which lead to erroneous display of the certificate in text format.");

  script_tag(name:"affected", value:"OpenSSL 1.1.0 before 1.1.0g and 1.0.2 before 1.0.2m");

  script_tag(name:"solution", value:"Upgrade to OpenSSL version 1.1.0g or 1.0.2m or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20171102.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

if(vers =~ "^1\.1\.0") {
  if(version_is_less(version:vers, test_version:"1.1.0g")) {
    Vuln = TRUE;
    fix = "1.1.0g";
  }
}
else if(vers =~ "^1\.0\.2") {
  if(version_is_less(version:vers, test_version:"1.0.2m")) {
    Vuln = TRUE;
    fix = "1.0.2m";
  }
}

if(Vuln) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
