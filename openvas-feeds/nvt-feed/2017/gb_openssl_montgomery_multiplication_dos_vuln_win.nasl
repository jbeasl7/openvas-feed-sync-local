# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810543");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2016-7055");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-01 16:25:00 +0000 (Thu, 01 Sep 2022)");
  script_tag(name:"creation_date", value:"2017-02-09 18:50:03 +0530 (Thu, 09 Feb 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OpenSSL Montgomery Multiplication Denial of Service Vulnerability - Windows");

  script_tag(name:"summary", value:"OpenSSL is prone to a Denial of Service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a carry propagating
  bug in the Broadwell-specific Montgomery multiplication procedure that
  handles input lengths divisible by, but longer than 256 bits.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause transient authentication, key negotiation failures or
  reproducible erroneous outcome of public-key operations with specially
  crafted input and also denial of service condition.");

  script_tag(name:"affected", value:"OpenSSL 1.1.0 before 1.1.0c and
  1.0.2 before 1.0.2k.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL version 1.1.0c or
  1.0.2k or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20170126.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/94242");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20161110.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Denial of Service");
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

if(vers =~ "^1\.1\.0")
  fix = "1.1.0c";
else if(vers =~ "^1\.0\.2")
  fix = "1.0.2k";

if(!fix)
  exit(99);

if(version_is_less(version:vers, test_version:fix)) {
  report = report_fixed_ver(installed_version:vers, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
