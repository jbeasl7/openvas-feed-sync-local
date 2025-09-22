# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:nidesoft:mp3_converter";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107108");
  script_version("2024-06-28T05:05:33+0000");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-06-28 05:05:33 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-12-19 11:19:11 +0530 (Mon, 19 Dec 2016)");

  script_name("Nidesoft MP3 Converter SEH Local Buffer Overflow Vulnerability - Windows");

  script_tag(name:"summary", value:"Nidesoft MP3 Converter is prone to an SEH local buffer overflow
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to execute
  arbitrary code on the system.");

  script_tag(name:"affected", value:"Nidesoft MP3 Converter 2.6.18 and prior on Windows.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/40917/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_nidesoft_mp3_conv_detect_win.nasl");
  script_mandatory_keys("Nidesoft/Mp3converter/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_equal(version:vers, test_version:"2.6.18")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None Available");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
