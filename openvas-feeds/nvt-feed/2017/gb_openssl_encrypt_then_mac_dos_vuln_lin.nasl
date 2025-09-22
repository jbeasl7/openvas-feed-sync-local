# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810702");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2017-3733");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-04-23 19:30:00 +0000 (Tue, 23 Apr 2019)");
  script_tag(name:"creation_date", value:"2017-02-21 15:59:18 +0530 (Tue, 21 Feb 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSL Encrypt-Then-Mac Extension Denial of Service Vulnerability - Linux");

  script_tag(name:"summary", value:"OpenSSL is prone to a Denial of Service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists, during a renegotiation
  handshake if the Encrypt-Then-Mac extension is negotiated where it was not in
  the original handshake (or vice-versa) then this can cause OpenSSL to crash
  (dependent on ciphersuite).");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial-of-service condition.");

  ## At the moment not sure about other version affected.
  script_tag(name:"affected", value:"OpenSSL version 1.1.0.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL version 1.1.0e or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20170216.txt");
  script_xref(name:"URL", value:"http://securityaffairs.co/wordpress/56343/security/openssl-cve-2017-3733.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
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

if(vers == "1.1.0") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.1.0e", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
