# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ftpshell:ftpshell";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107083");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-14 16:34:55 +0700 (Mon, 14 Nov 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_name("FTPShell Client 5.24 Buffer Overflow");
  script_xref(name:"URL", value:"http://hyp3rlinx.altervista.org/advisories/FTPSHELL-v5.24-BUFFER-OVERFLOW.txt");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_ftpshell_client_detect.nasl");
  script_mandatory_keys("FTPShell/Client/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let the user execute local arbitrary code execution by overwriting several registers on the stack and controlling program execution flow.");
  script_tag(name:"affected", value:"FTPShell Client 5.24.");
  script_tag(name:"insight", value:"ftpshell.exe client has a buffer overflow entry point in the 'Address' input field used to connect to an FTP server.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"FTPShell Client is prone to a buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!shellVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:shellVer, test_version:"5.24")){
  report = report_fixed_ver(installed_version:shellVer, fixed_version:"None Available");
  security_message(data:report, port:0);
  exit(0);
}

exit(99);
