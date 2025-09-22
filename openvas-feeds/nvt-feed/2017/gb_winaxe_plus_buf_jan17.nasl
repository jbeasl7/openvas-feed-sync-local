# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:winaxe:plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107126");
  script_version("2025-07-16T05:43:53+0000");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-07-16 05:43:53 +0000 (Wed, 16 Jul 2025)");
  script_tag(name:"creation_date", value:"2017-01-17 16:11:25 +0530 (Tue, 17 Jan 2017)");
  script_name("WinaXe Plus Buffer Overflow Vulnerability - Windows");

  script_tag(name:"summary", value:"WinaXe Plus is prone to a buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Exploitation of these vulnerabilities could allow a remote attacker to cause an affected player to crash and,
  in some cases, could allow a remote attacker to execute arbitrary code on the system of a targeted user.");

  script_tag(name:"affected", value:"WinaXe Plus 8.7.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/41073/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_winaxe_plus_detection.nasl");
  script_mandatory_keys("Winaxeplus/Win/installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");


if(!Ver = get_app_version(cpe:CPE)){
  exit(0);
}

if (version_is_equal(version: Ver, test_version:"8.7"))
{
  report = report_fixed_ver(installed_version:Ver, fixed_version:"None Available");
  security_message(data:report);
  exit(0);
}


