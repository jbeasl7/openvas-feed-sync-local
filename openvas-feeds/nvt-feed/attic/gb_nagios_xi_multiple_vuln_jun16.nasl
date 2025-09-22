# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807835");
  script_version("2025-01-17T15:39:18+0000");
  script_tag(name:"deprecated", value:TRUE);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"creation_date", value:"2016-06-08 16:38:53 +0530 (Wed, 08 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_analysis");
  script_name("Nagios XI Multiple Vulnerabilities (Jun 2016)");

  script_tag(name:"summary", value:"Nagios XI is prone to multiple vulnerabilities.

  This VT has been deprecated and replaced by the VT with the OID: 1.3.6.1.4.1.25623.1.0.105749.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to execute sql query or not.");

  script_tag(name:"insight", value:"Multiple errors are due to:

  - Insufficient sanitization of input passed via 'host' and 'service'
    GET parameters in the 'nagiosim.php' page.

  - Unescaped user input being passed to shell functions as an argument.

  - An insecure implementation of the application's component upload functionality.

  - An insecure implementation of the password reset functionality.

  - Multiple server-side request forgery vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct command injection, gain elevated privileges, conduct
  server side request forgery attacks, conduct account hijacking and inject or
  manipulate SQL queries in the back-end database, allowing for the manipulation
  or disclosure of arbitrary data.");

  script_tag(name:"affected", value:"Nagios XI version 5.2.7 and prior.");

  script_tag(name:"solution", value:"Update to Nagios XI version 5.2.8.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/39899");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/137293");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2016/Jun/9");
  script_xref(name:"URL", value:"http://www.security-assessment.com/files/documents/advisory/NagiosXI-Advisory.pdf");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  exit(0);
}

exit(66); ## This VT is deprecated as addressed in gb_nagios_xi_multiple_vulnerabilities_06_16.nasl (OID:1.3.6.1.4.1.25623.1.0.105749)
