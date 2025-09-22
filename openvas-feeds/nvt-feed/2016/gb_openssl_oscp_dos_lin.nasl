# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107050");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-6304");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"creation_date", value:"2016-09-26 06:40:16 +0200 (Mon, 26 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-16 13:18:00 +0000 (Tue, 16 Aug 2022)");

  script_name("OpenSSL OCSP Status Request extension unbounded memory growth Vulnerability - Linux");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20160922.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"OpenSSL is prone to a Denial of Service (DoS) vulnerability.");

  script_tag(name:"insight", value:"OpenSSL suffers from the possibility of DoS attack through sending a large OCSP Status
  Request extensions which lead to unbounded memory growth on the server which in turn lead to denial of service.");

  script_tag(name:"impact", value:"Successful exploitation could result in service crash.");

  script_tag(name:"affected", value:"OpenSSL 1.1.0 and previous versions.");

  script_tag(name:"solution", value:"OpenSSL 1.1.0 users should upgrade to 1.1.0a. OpenSSL 1.0.2 users should upgrade to 1.0.2i. OpenSSL 1.0.1 users should upgrade to 1.0.1u.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");

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

if(vers =~ "^1\.1\.0" && version_is_less(version:vers, test_version:"1.1.0a")) {
  fix = "1.1.0a";
  VUL = TRUE;
}
else if(vers =~ "^1\.0\.2" && version_is_less(version:vers, test_version:"1.0.2i")) {
  fix = "1.0.2i";
  VUL = TRUE;
}
else if(vers =~ "^1\.0\.1" && version_is_less(version:vers, test_version:"1.0.1u")) {
  fix = "1.0.1u";
  VUL = TRUE;
}

if(VUL) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
