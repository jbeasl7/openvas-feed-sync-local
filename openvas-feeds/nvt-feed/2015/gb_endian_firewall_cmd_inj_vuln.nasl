# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:endian_firewall:endian_firewall";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805758");
  script_version("2024-03-04T14:37:58+0000");
  script_cve_id("CVE-2015-5082");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2015-10-12 17:26:17 +0530 (Mon, 12 Oct 2015)");
  script_name("Endian Firewall OS Command Injection Vulnerability");

  script_tag(name:"summary", value:"Endian Firewall is prone to a command injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to 'NEW_PASSWORD_1' or
  'NEW_PASSWORD_2' parameter to  cgi-bin/chpasswd.cgi are not properly filtered.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to read arbitrary files on the affected application.");

  script_tag(name:"affected", value:"Endian Firewall before version 3.0.");

  script_tag(name:"solution", value:"Upgrade to Endian Firewall version 3.0
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/37426");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/37428");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_endian_firewall_version.nasl");
  script_mandatory_keys("endian_firewall/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_less(version:version, test_version:"3.0.0")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"3.0.0");
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
