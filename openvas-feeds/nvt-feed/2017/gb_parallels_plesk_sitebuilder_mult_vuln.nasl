# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:parallels:parallels_plesk_sitebuilder";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812279");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2017-12-27 12:18:56 +0530 (Wed, 27 Dec 2017)");
  script_name("Parallels Plesk Sitebuilder Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Parallels Plesk Sitebuilder is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send the crafted http GET request
  and check whether it is able to bypass authentication or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple input validation errors in all modules of the page 'Wizard/Edit.aspx'.

  - An improper access control on pages 'Wizard/Pages.aspx' and 'Wizard/Edit.aspx<F9>
    and loginpage.

  - Multiple input validation errors while downloading and uploading of files.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to execute arbitrary script, download and upload arbitrary files and
  bypass authentication.");

  script_tag(name:"affected", value:"Parallels Plesk Sitebuilder 4.5.");

  script_tag(name:"solution", value:"No known solution was made available for at least one
  year since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/34593");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_parallels_plesk_sitebuilder_remote_detect.nasl");
  script_mandatory_keys("Parallels/Plesk/Sitebuilder/Installed");
  script_require_ports("Services/www", 2006);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!get_app_location(cpe:CPE, port:port, nofork:TRUE))
  exit(0);

url = "/Wizard/Default.aspx";

if(http_vuln_check(port:port, url:url, check_header:TRUE,
                   pattern:"Copyright.*Parallels",
                   extra_check:make_list('>Design', '>Pages', '>Publish', '>Apply changes?'))) {
  report = http_report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
