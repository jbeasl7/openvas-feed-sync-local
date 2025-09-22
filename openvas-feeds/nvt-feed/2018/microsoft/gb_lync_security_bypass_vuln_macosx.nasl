# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:lync";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814214");
  script_version("2023-10-13T16:09:03+0000");
  script_cve_id("CVE-2018-8474");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-13 16:09:03 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-28 16:28:00 +0000 (Thu, 28 Feb 2019)");
  script_tag(name:"creation_date", value:"2018-09-18 11:05:15 +0530 (Tue, 18 Sep 2018)");
  script_name("Microsoft Lync Security Feature Bypass Vulnerability - Mac OS X");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an insufficient
  sanitization of crafted messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  cause a targeted Lync for Mac 2011 user's system to browse to an attacker-specified
  website or automatically download file types on the operating system's safe file
  type list.");

  script_tag(name:"affected", value:"Microsoft Lync for Mac 2011.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8474");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_lync_detect_macosx.nasl");
  script_mandatory_keys("Microsoft/Lync/MacOSX/Version");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(vers =~ "^14\.") {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
