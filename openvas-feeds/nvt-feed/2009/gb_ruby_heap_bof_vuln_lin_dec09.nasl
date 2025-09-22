# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ruby-lang:ruby";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900726");
  script_version("2025-09-09T05:38:49+0000");
  script_tag(name:"last_modification", value:"2025-09-09 05:38:49 +0000 (Tue, 09 Sep 2025)");
  script_tag(name:"creation_date", value:"2009-12-23 08:41:41 +0100 (Wed, 23 Dec 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4124");
  script_name("Ruby Interpreter Heap Overflow Vulnerability (Dec 2009) - Linux");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37660");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37278");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3471");
  script_xref(name:"URL", value:"http://www.ruby-lang.org/en/news/2009/12/07/heap-overflow-in-string");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_ruby_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("ruby/detected", "Host/runs_unixoide");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary code, corrupt
  the heap area to execute the crafted malicious shellcode into the system
  registers to take control over the remote machine.");

  script_tag(name:"affected", value:"Ruby Interpreter version 1.9.1 before 1.9.1 Patchlevel 376.");

  script_tag(name:"insight", value:"The flaw is due to improper sanitization check while processing user
  supplied input data to the buffer inside 'String#ljust', 'String#center' and
  'String#rjust' methods.");

  script_tag(name:"summary", value:"Ruby Interpreter is prone to a heap overflow vulnerability.");

  script_tag(name:"solution", value:"Update to version 1.9.1-p376 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe: CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "1.9.1", test_version2: "1.9.1.375" ) ) {
  report = report_fixed_ver( installed_version: version, vulnerable_range: "1.9.1 - 1.9.1.p375", install_path: location );
  security_message( port: port, data: report );
  exit( 0 );
}

exit( 99 );
