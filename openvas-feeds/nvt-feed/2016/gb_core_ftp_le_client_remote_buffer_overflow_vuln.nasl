# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:coreftp:core_ftp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810305");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-12-08 12:40:39 +0530 (Thu, 08 Dec 2016)");
  script_name("Core FTP LE Client 'SSH/SFTP' Remote Buffer Overflow Vulnerability");

  script_tag(name:"summary", value:"Core FTP Client is prone to remote buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when core ftp client
  does not handle long string of junk from the malicious FTP server
  using SSH/SFTP protocol.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  denial of service.");

  script_tag(name:"affected", value:"Core FTP LE (Client) v2.2 build 1883.");

  script_tag(name:"solution", value:"Update to version 2.2 (build 1885).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40828");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_core_ftp_le_client_detect.nasl");
  script_mandatory_keys("Core/FTP/Client/Win/Ver");
  script_xref(name:"URL", value:"https://www.coreftp.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!ftpVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:ftpVer, test_version:"2.2.1883.0"))
{
  report = report_fixed_ver(installed_version:ftpVer, fixed_version:"2.2.1885");
  security_message(data:report);
  exit(0);
}
