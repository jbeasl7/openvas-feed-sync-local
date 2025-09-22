# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:symphony-cms:symphony_cms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801220");
  script_version("2024-03-04T14:37:58+0000");
  script_tag(name:"last_modification", value:"2024-03-04 14:37:58 +0000 (Mon, 04 Mar 2024)");
  script_tag(name:"creation_date", value:"2010-06-11 14:27:58 +0200 (Fri, 11 Jun 2010)");
  script_cve_id("CVE-2010-2143");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Symphony CMS Directory traversal vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12809/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40441");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/1005-exploits/symphony-lfi.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_symphony_cms_detect.nasl");
  script_mandatory_keys("symphony/installed");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to view files and
execute local scripts in the context of the web server process, which may aid
in further attacks.");
  script_tag(name:"affected", value:"Symphony CMS Version 2.0.7");
  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input
via the 'mode' parameter in 'index.php' that allows the attackers to view files
and execute local scripts in the context of the web server.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"Symphony CMS is prone to a directory traversal vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!version = get_app_version(cpe:CPE, port:port))
  exit(0);

if(version_is_equal(version:version, test_version:"2.0.7")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"None");
  security_message(port:port, data:report);
  exit(0);
}

exit(0);
