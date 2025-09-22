# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813793");
  script_version("2024-02-19T05:05:57+0000");
  script_cve_id("CVE-2016-7056");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-02-19 05:05:57 +0000 (Mon, 19 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:19:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2018-09-11 11:49:25 +0530 (Tue, 11 Sep 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("OpenSSL: Information Disclosure Vulnerability (CVE-2016-7056) - Windows");

  script_tag(name:"summary", value:"OpenSSL is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient setting
  in the 'BN_FLG_CONSTTIME' flag for nonces, which could trigger a failure to take
  a secure code path in the BN_mod_inverse method that results in a cache-timing
  condition.");

  script_tag(name:"impact", value:"Successful exploitation will allow a malicious
  user with local access to recover ECDSA P-256 private keys.");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.1u and prior.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL version 1.1.0 or 1.0.2
  or later. See the references for more details.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=52295");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/95375");
  script_xref(name:"URL", value:"https://eprint.iacr.org/2016/1195");
  script_xref(name:"URL", value:"https://git.openssl.org/?p=openssl.git;a=commit;h=8aed2a7548362e88e84a7feb795a3a97e8395008");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_openssl_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssl/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE))
 exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less_equal(version:vers, test_version:"1.0.1u")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.1.0 or 1.0.2", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
