# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:allplayer:allplayer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805101");
  script_version("2024-02-08T05:05:59+0000");
  script_cve_id("CVE-2013-7409");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-11-21 11:25:38 +0530 (Fri, 21 Nov 2014)");
  script_name("ALLPlayer Buffer Overflow Vulnerability (Nov 2014) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_allplayer_detect_win.nasl");
  script_mandatory_keys("ALLPlayer/Win/Ver");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/32074");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62926");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/28855");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/32041");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/29798");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/29549");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125519");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123554");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124161");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/123986");

  script_tag(name:"summary", value:"ALLPlayer is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to improper handling of M3U file.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to cause a buffer overflow, resulting in a denial of service or potentially
  allowing the execution of arbitrary code.");

  script_tag(name:"affected", value:"ALLPlayer version 5.6.2 through 5.8.1
  on Windows.");

  script_tag(name:"solution", value:"No known solution was made available for at
  least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE))
  exit(0);

if(version_in_range(version:playerVer, test_version:"5.6.2", test_version2:"5.8.1")) {
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"None");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
