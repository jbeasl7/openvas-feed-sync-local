# SPDX-FileCopyrightText: 2005 Digital Defense Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10998");
  script_version("2023-07-07T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-07-07 05:05:26 +0000 (Fri, 07 Jul 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0507", "CVE-1999-0508");
  script_name("Shiva LanRover Blank Password (Telnet)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2005 Digital Defense Inc.");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/shiva/lanrover/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Telnet to this device and change the
  password for the root account via the passwd command. Please ensure any other
  accounts have strong passwords set.");

  script_tag(name:"summary", value:"The Shiva LanRover has no password set for the
  root user account.");

  script_tag(name:"impact", value:"An attacker is able to telnet to this system and
  gain access to any phone lines attached to this device. Additionally, the LanRover
  can be used as a relay point for further attacks via the telnet and rlogin functionality
  available from the administration shell.");

  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("dump.inc");

port = 23;
if(!get_port_state(port))exit(0);

banner = telnet_get_banner(port:port);
if ( ! banner || "@ Userid:" >!< banner ) exit(0);

soc = open_sock_tcp(port);
if(soc)
{
  r = telnet_negotiate(socket:soc);

  if("@ Userid:" >< r)
  {
    send(socket:soc, data:string("root\r\n"));
    r = recv(socket:soc, length:4096);

    if("Password?" >< r)
    {
      send(socket:soc, data:string("\r\n"));
      r = recv(socket:soc, length:4096);

      if ("Shiva LanRover" >< r)
      {
        security_message(port:port);
      }
    }
  }
  close(soc);
}