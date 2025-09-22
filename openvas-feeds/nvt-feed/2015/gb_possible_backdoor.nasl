# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105238");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-03-16 10:53:07 +0100 (Mon, 16 Mar 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Possible Backdoor");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Malware");
  script_dependencies("find_service2.nasl");
  script_mandatory_keys("possible/backdoor");

  script_tag(name:"summary", value:"Look for potential backdoors.");

  script_tag(name:"solution", value:"Clean up the target host from the potential backdoor.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if( port = get_kb_item( "possible/backdoor" ) ) {
  name = get_kb_item( "backdoor/name" );
  security_message( port:port, data:"A backdoor (" + name + ") seems to be running on this port." );
  exit( 0 );
}

exit( 99 );
