# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806902");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2014-9749");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-12-23 13:34:49 +0530 (Wed, 23 Dec 2015)");
  script_name("Squid 3.4.4 - 3.4.11, 3.5.0.1 - 3.5.1 Nonce Replay Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_squid_http_detect.nasl");
  script_mandatory_keys("squid/detected");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2015/10/11/4");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77040");
  script_xref(name:"URL", value:"http://bugs.squid-cache.org/show_bug.cgi?id=4066");

  script_tag(name:"summary", value:"Squid is prone to a security bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some unspecified error
  in digest_authentication.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  disabled user or users with changed password to access the squid service with
  old credentials.");

  script_tag(name:"affected", value:"Squid proxy versions 3.4.4 through 3.4.11 and 3.5.0.1
  through 3.5.1.");

  script_tag(name:"solution", value:"Update to version 3.4.12, 3.5.2 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!vers = get_app_version(cpe:CPE, port:port))
  exit(0);

if(!vers =~ "^3\.")
  exit(0);

if(version_in_range(version:vers, test_version:"3.4.4", test_version2:"3.4.11")){
  VULN = TRUE;
  Fix = "3.4.12";
}

else if(version_in_range(version:vers, test_version:"3.5.0.1", test_version2:"3.5.1")){
  VULN = TRUE;
  Fix = "3.5.2";
}

if(VULN){
  report = report_fixed_ver(installed_version:vers, fixed_version:Fix);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
