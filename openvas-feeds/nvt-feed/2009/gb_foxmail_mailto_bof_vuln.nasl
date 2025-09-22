# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800220");
  script_version("2025-02-21T15:40:05+0000");
  script_tag(name:"last_modification", value:"2025-02-21 15:40:05 +0000 (Fri, 21 Feb 2025)");
  script_tag(name:"creation_date", value:"2009-01-08 14:06:04 +0100 (Thu, 08 Jan 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2008-5839");

  script_name("FoxMail Client Buffer Overflow vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_tencent_foxmail_smb_login_detect.nasl");
  script_mandatory_keys("foxmail/detected");

  script_tag(name:"summary", value:"FoxMail Client is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This flaw is due to lack of sanitization and boundary check in
  the user supplied data which can be exploited by adding a long URL length in the HREF attribute
  of an A element.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to insert a long
  crafted URI in the MAILTO field and can cause a stack overflow to the application.");

  script_tag(name:"affected", value:"Foxmail version 6.5 or prior on Windows.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://www.sebug.net/exploit/4681");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31294");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/45343");

  exit(0);
}

CPE = "cpe:/a:tencent:foxmail";

include("host_details.inc");
include("version_func.inc");

if(!version = get_app_version(cpe:CPE)) exit(0);

if(version_is_less_equal(version:version, test_version:"6.5")){
  report = report_fixed_ver(installed_version:version, fixed_version:"None");
  security_message(data:report, port:0);
  exit(0);
}

exit(0);
