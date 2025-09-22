# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802726");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-04-09 18:56:54 +0530 (Mon, 09 Apr 2012)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft SMB Signing Disabled");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Windows");
  script_dependencies("cifs445.nasl",
                      "netbios_name_get.nasl", # For SMB/name in kb_smb_name()
                      "logins.nasl"); # For different SMB configuration parameters
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"Checks if SMB Signing is disabled at the remote SMB server.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smb_nt.inc");

name = kb_smb_name();
port = kb_smb_transport();

if(!soc = open_sock_tcp(port))
  exit(0);

response = smb_session_request(soc:soc, remote:name);
if(!response) {
  close(soc);
  exit(0);
}

# SMB Negotiate Protocol Response
# If SMB signing is disabled, then Security Mode: 0x03
prot = smb_neg_prot(soc:soc);
close(soc);

if(prot && ord(prot[39]) == 3) {
  log_message(port:port, data:"SMB Signing is disabled at the server.");
  exit(0);
}

exit(99);
