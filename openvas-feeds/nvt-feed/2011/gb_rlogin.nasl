# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901202");
  script_version("2025-03-05T05:38:53+0000");
  script_tag(name:"last_modification", value:"2025-03-05 05:38:53 +0000 (Wed, 05 Mar 2025)");
  script_tag(name:"creation_date", value:"2011-08-25 09:25:35 +0200 (Thu, 25 Aug 2011)");

  script_cve_id("CVE-1999-0651");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("The rlogin service is running");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_rlogin_detect.nasl");
  script_family("Useless services");
  script_mandatory_keys("rlogin/detected");

  script_tag(name:"summary", value:"This remote host is running a rlogin service.");

  script_tag(name:"insight", value:"rlogin has several serious security problems,

  - all information, including passwords, is transmitted unencrypted.

  - .rlogin (or .rhosts) file is easy to misuse (potentially allowing
  anyone to login without a password)");

  script_tag(name:"solution", value:"Disable the rlogin service and use alternatives like SSH instead.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include( "host_details.inc" );

if( ! port = get_kb_item( "rlogin/port" ) ) exit( 0 );

report = "The rlogin service is running on the target system.";
security_message( data: report, port: port );

exit( 0 );
