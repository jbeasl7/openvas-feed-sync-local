# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ipswitch:ws_ftp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902171");
  script_version("2023-12-01T05:05:39+0000");
  script_cve_id("CVE-2009-4775");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Ipswitch WS_FTP Professional < 12.2 'HTTP' Response Format String Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Windows");
  script_dependencies("gb_ipswitch_ws_ftp_pro_smb_login_detect.nasl");
  script_mandatory_keys("ipswitch/ws_ftp/professional/detected");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9607");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36297");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/53098");
  script_xref(name:"URL", value:"http://www.juniper.net/security/auto/vulnerabilities/vuln36297.html");
  script_xref(name:"URL", value:"http://www.packetstormsecurity.org/0909-exploits/nocoolnameforawsftppoc.pl.txt");

  script_tag(name:"summary", value:"Ipswitch WS_FTP Professional is prone to a format string
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to error in 'formatted-printing()' function. It
  fails to properly sanitize user supplied input before passing it as the format specifier.
  Specifically, the issue presents itself when the client parses specially crafted responses for a
  malicious HTTP server.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary
  code in the context of the vulnerable application, failed exploit attempts will likely result in a
  denial-of-service condition.");

  script_tag(name:"affected", value:"Ipswitch WS_FTP Professional prior to version 12.2.

  Note: Versions prior to 12.x were 2006 through 2007 which are assumed to be affected as well.");

  script_tag(name:"solution", value:"Update to version 12.2 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

# nb: See note in the affected tag above
if (version =~ "^200[67]" ||
    version_is_less(version:version, test_version:"12.2")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"12.2", install_path:location);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
