# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108554");
  script_version("2024-07-10T05:05:27+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-10 05:05:27 +0000 (Wed, 10 Jul 2024)");
  script_tag(name:"creation_date", value:"2019-02-26 13:55:27 +0100 (Tue, 26 Feb 2019)");
  script_name("OpenVAS / Greenbone Vulnerability Manager (GVM) Default Credentials (OMP/GMP Protocol)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_dependencies("gb_openvas_manager_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/omp_gmp", 9390);
  script_mandatory_keys("openvasmd_gvmd/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote OpenVAS / Greenbone Vulnerability Manager (GVM) is
  installed / configured in a way that it has account(s) with default passwords enabled.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Tries to login with known default credentials via the OMP/GMP
  protocol.");

  script_tag(name:"solution", value:"Change the password of the mentioned account(s).");

  script_tag(name:"qod_type", value:"exploit");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("host_details.inc");

cpe_list = make_list( "cpe:/a:openvas:openvas_manager", "cpe:/a:greenbone:greenbone_vulnerability_manager" );

# nb:
# - Keep this list in sync with 2015/gb_gsa_http_default_credentials.nasl
# - We might want to use a list and a separator between the credentials (like e.g. #---#) in the
#   future so that we don't need the "Admin", "aDmin" and similar handling below
creds = make_array(

  # OpenVAS Virtual Appliance
  "admin", "admin",

  # Docker image from https://github.com/falegk/openvas_pg#usage
  "sadmin", "changeme",

  # Docker image from https://github.com/mikesplain/openvas-docker#usage
  # nb: The username is "admin" but the uppercase "A" is used here to have a different array index
  "Admin", "openvas",

  # Docker image from:
  # - https://github.com/Secure-Compliance-Solutions-LLC/GVM-Docker
  # - https://github.com/onvio/gvm-openvas-scanner/blob/main/README.md#usage
  # nb: The username is "admin" but the uppercase "D" is used here to have a different array index
  "aDmin", "adminpassword",

  # Created by the following install script: https://github.com/yu210148/gvm_install
  "gvmadmin", "StrongPass",

  # Created by the following install script: https://github.com/itiligent/Easy-OpenVAS-Builder
  # nb: The username is "admin" but the uppercase "M" is used here to have a different array index
  "adMin", "password",

  # The ones below might be used from time to time out there
  "observer", "observer",
  "webadmin", "webadmin",
  "gmp", "gmp",
  "omp", "omp"
);

report = 'It was possible to login using the following credentials (username:password:role):\n';

if( ! infos = get_app_port_from_list( cpe_list:cpe_list, service:"omp_gmp" ) )
  exit( 0 );

CPE  = infos["cpe"];
port = infos["port"];

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

foreach username( keys( creds ) ) {

  soc = open_sock_tcp( port );
  if( ! soc )
    continue;

  password = creds[username];
  username = tolower( username ); # nb: See comments above

  # https://docs.greenbone.net/API/GMP/gmp-22.04.html#command_authenticate
  req = "<authenticate><credentials><username>" + username + "</username><password>" + password + "</password></credentials></authenticate>";
  send( socket:soc, data:req + '\r\n' );
  res = recv( socket:soc, length:1024 );
  close( soc );

  if( res && '<authenticate_response status="200" status_text="OK">' >< res ) {
    role  = "unknown";
    _role = eregmatch( string:res, pattern:"<role>(.+)</role>" );
    if( _role[1] )
      role = _role[1];

    vuln    = TRUE;
    report += '\n' + username + ":" + password + ":" + role;
  }
}

if( vuln ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
