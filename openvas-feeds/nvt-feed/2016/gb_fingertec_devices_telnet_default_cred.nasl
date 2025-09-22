# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807525");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-03-16 15:57:40 +0530 (Wed, 16 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("FingerTec Devices Default Credentials (Telnet)");

  script_tag(name:"summary", value:"FingerTec device is using known default credentials.");

  script_tag(name:"vuldetect", value:"Check if it is possible to do telnet
  login into the FingerTec device.");

  script_tag(name:"insight", value:"The flaw is due to default user:passwords
  which is publicly known and documented.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain unauthorized root access to affected devices and completely
  compromise the devices.");

  script_tag(name:"affected", value:"FingerTec Devices.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://blog.infobytesec.com/2014/07/perverting-embedded-devices-zksoftware_2920.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/fingertex/device/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("telnet_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("dump.inc");

fingport = telnet_get_port(default:23);
if(!banner = telnet_get_banner(port:fingport)) exit(0);
if("ZEM" >!< banner) exit(0);

soc = open_sock_tcp(fingport);
if(!soc) exit(0);

creds = make_array("root", "founder88",
                   "root", "colorkey",
                   "root", "solokey",
                   "root","swsbzkgn",
                   "admin", "admin",
                   "888", "manage",
                   "manage", "888",
                   "asp", "test",
                   "888", "asp",
                   "root", "root",
                   "admin","1234");

foreach cred ( keys( creds ) )
{
  recv = recv( socket:soc, length:2048 );
  if ("login:" >< recv)
  {
    send(socket:soc, data: cred + '\r\n');
    recv = recv(socket:soc, length:128);
    if("Password:" >< recv)
    {
      send(socket:soc, data: creds[cred] + '\r\n');
      recv = recv(socket:soc, length:1024);

      if(recv =~ "BusyBox v([0-9.]+)")
      {
        report += "\n\n" + cred + ":" + creds[cred] + "\n";
        security_message(port:fingport, data:report);
        close(soc);
      }
    }
  }
}

close(soc);
