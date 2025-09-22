# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804417");
  script_version("2025-08-21T05:40:06+0000");
  script_tag(name:"last_modification", value:"2025-08-21 05:40:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"creation_date", value:"2014-03-20 12:13:13 +0530 (Thu, 20 Mar 2014)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2014-125121");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Array Networks vxAG/xAPV Multiple Vulnerabilities (Mar 2014)");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"Array Networks vxAG/xAPV is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Tries to login via SSH using known default credentials.");

  script_tag(name:"insight", value:"The following flaws exist:

  - The program uses insecure world writable permissions for the '/ca/bin/monitor.sh' file.

  - The 'mfg' account has a password of 'mfg' and the 'sync' account has a
  password of 'click1', which is publicly known and documented.

  - CVE-2014-125121: Privilege escalation vulnerability caused by a combination of hardcoded SSH
  credentials (or SSH private key) and insecure permissions on a startup script");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to gain unauthorized
  root access to affected devices and completely compromise the devices.");

  script_tag(name:"affected", value:"Array Networks vxAG 9.2.0.34 and vAPV 8.3.2.17 appliances.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General
  solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125761");
  script_xref(name:"URL", value:"https://web.archive.org/web/20200229065329/http://www.securityfocus.com/bid/66299");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/32440");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port(default:22);

if(ssh_dont_try_login(port:port))
  exit(0);

if(!soc = open_sock_tcp(port))
  exit(0);

user = "mfg";
pass = "mfg";

login = ssh_login(socket:soc, login:user, password:pass, priv:NULL, passphrase:NULL);
if(login == 0)
{
  cmd = "id";
  res = ssh_cmd(socket:soc, cmd:cmd);

  if(ereg(pattern:"uid=[0-9]+.*gid=[0-9]+", string:res))
  {
    report = 'It was possible to login as user "' + user + '" with password "' + pass + '" and to execute the "' + cmd + '" command. Result:\n\n' + res;
    security_message(port:port, data:report);
    close(soc);
    exit(0);
  }
}

close(soc);
