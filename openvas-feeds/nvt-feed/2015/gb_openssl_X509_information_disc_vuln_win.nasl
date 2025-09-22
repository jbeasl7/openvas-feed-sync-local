# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806655");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2015-3195");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-19 17:27:00 +0000 (Tue, 19 Jan 2021)");
  script_tag(name:"creation_date", value:"2015-12-23 11:08:20 +0530 (Wed, 23 Dec 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OpenSSL 'X509_ATTRIBUTE' Information Disclosure Vulnerability - Windows");

  script_tag(name:"summary", value:"OpenSSL is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in
  'ASN1_TFLG_COMBINE' implementation within crypto/asn1/tasn_dec.c script.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"OpenSSL versions before 0.9.8zh, 1.0.0 before
  1.0.0t, 1.0.1 before 1.0.1q, and 1.0.2 before 1.0.2e Windows");

  script_tag(name:"solution", value:"Upgrade to OpenSSL 0.9.8zh or 1.0.0t or
  1.0.1q or 1.0.2e or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://openssl.org/news/secadv/20151203.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
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

if(vers =~ "^0\.9\.8") {
  if(version_is_less(version:vers, test_version:"0.9.8zh")) {
    fix = "0.9.8zh";
    VULN = TRUE;
  }
}
else if(vers =~ "^1\.0\.0") {
  if(version_is_less(version:vers, test_version:"1.0.0t")) {
    fix = "1.0.0t";
    VULN = TRUE;
  }
}
else if(vers =~ "^1\.0\.1") {
  if(version_is_less(version:vers, test_version:"1.0.1q")) {
    fix = "1.0.1q";
    VULN = TRUE;
  }
}
else if(vers =~ "^1\.0\.2") {
  if(version_is_less(version:vers, test_version:"1.0.2e"))
  {
    fix = "1.0.2e";
    VULN = TRUE;
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
