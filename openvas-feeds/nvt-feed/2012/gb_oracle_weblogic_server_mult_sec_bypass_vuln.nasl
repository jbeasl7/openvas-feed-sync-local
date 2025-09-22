# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:bea:weblogic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802446");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"5.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-08-28 01:34:53 +0530 (Tue, 28 Aug 2012)");

  script_name("Oracle WebLogic Server Multiple Security Bypass Vulnerabilities");

  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2012/Aug/50");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54839");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54870");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20319/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/20318/");
  script_xref(name:"URL", value:"http://retrogod.altervista.org/9sg_ora2.htm");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_oracle_weblogic_consolidation.nasl");
  script_mandatory_keys("oracle/weblogic/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code under
  the context of the application.");

  script_tag(name:"affected", value:"Oracle WebLogic Server version 12c (12.1.1).");

  script_tag(name:"insight", value:"- Soap interface exposes the 'deleteFile' function which could allow to
  delete arbitrary files with administrative privileges on the target server through a directory traversal
  vulnerability.

  - A web service called 'FlashTunnelService' which can be reached without prior authentication and processes
    incoming SOAP requests.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"summary", value:"Oracle WebLogic Server is prone to multiple security bypass vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!vers = get_app_version(cpe:CPE, nofork:TRUE))
  exit(0);

if (version_is_equal(version:vers, test_version:"12.1.1.0")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
