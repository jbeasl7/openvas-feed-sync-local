# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111108");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2016-07-06 16:00:00 +0200 (Wed, 06 Jul 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Linux Home Folder Accessible (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script attempts to identify files of a linux home folder
  accessible at the webserver.");

  script_tag(name:"vuldetect", value:"Check the response if files from a home folder are accessible.");

  script_tag(name:"insight", value:"Currently the script is checking for the following files:

  - /.ssh/authorized_keys

  - /.ssh/config

  - /.ssh/known_hosts

  - /.ssh/identity

  - /.ssh/id_rsa

  - /.ssh/id_rsa.pub

  - /.ssh/id_dsa

  - /.ssh/id_dsa.pub

  - /.ssh/id_dss

  - /.ssh/id_dss.pub

  - /.ssh/id_ecdsa

  - /.ssh/id_ecdsa.pub

  - /.ssh/id_ed25519

  - /.ssh/id_ed25519.pub

  - /.mysql_history

  - /.sqlite_history

  - /.psql_history

  - /.sh_history

  - /.bash_history

  - /.profile

  - /.bashrc");

  script_tag(name:"impact", value:"Based on the information provided in these files an attacker
  might be able to gather additional info.");

  script_tag(name:"solution", value:"A users home folder shouldn't be accessible via a webserver.
  Restrict access to it or remove it completely.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_timeout(600);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

files = make_array( "/.ssh/authorized_keys", "^(ecdsa-sha2-nistp256|ssh-rsa|ssh-dsa|ssh-dss|ssh-ed25519)",
                    "/.ssh/config", "^\s*(Host (\*|a-z])|(HostName|LogLevel|Compression|IdentityFile|ForwardAgent|ForwardX11|ForwardX11Trusted|ProxyCommand|LocalForward) )",
                    "/.ssh/known_hosts", "(ecdsa-sha2-nistp256|ssh-rsa|ssh-dsa|ssh-dss|ssh-ed25519)",
                    "/.ssh/identity", "^SSH PRIVATE KEY FILE FORMAT",
                    # Some examples for private key names can be seen at e.g.:
                    # https://en.wikibooks.org/wiki/OpenSSH/Client_Configuration_Files#Local_Account_Public_/_Private_Key_Pairs
                    "/.ssh/id_rsa", "^-----(BEGIN|END) (RSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_rsa.pub", "^ssh-rsa",
                    "/.ssh/id_dsa", "^-----(BEGIN|END) (DSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_dsa.pub", "^ssh-dsa",
                    "/.ssh/id_dss", "^-----(BEGIN|END) (DSS|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_dss.pub", "^ssh-dss",
                    "/.ssh/id_ecdsa", "^-----(BEGIN|END) (EC|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_ecdsa.pub", "^ecdsa-sha2-nistp256",
                    "/.ssh/id_ed25519", "^-----(BEGIN|END) (ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_ed25519.pub", "^ssh-ed25519",
                    "/.ssh/id_ecdsa-sk", "^-----(BEGIN|END) (EC|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_ed25519-sk", "^-----(BEGIN|END) (ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_ecdsa-sk_rk", "^-----(BEGIN|END) (EC|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_ed25519-sk_rk", "^-----(BEGIN|END) (ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    # Additional ones seen in examples / guides like e.g.:
                    # https://cryptomonkeys.com/2015/04/generating-ssh-keys/
                    "/.ssh/id_rsa_1024", "^-----(BEGIN|END) (RSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_rsa_2048", "^-----(BEGIN|END) (RSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_rsa_3072", "^-----(BEGIN|END) (RSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.ssh/id_rsa_4096", "^-----(BEGIN|END) (RSA|ENCRYPTED|OPENSSH) PRIVATE KEY-----",
                    "/.mysql_history", "^(INSERT INTO |DELETE FROM |(DROP|CREATE) TABLE |(DROP|CREATE) (DATABASE|SCHEMA) |SELECT ALL |GRANT ALL ON |FLUSH PRIVILEGES)",
                    "/.sqlite_history", "^(INSERT INTO |DELETE FROM |(DROP|CREATE) TABLE |(DROP|CREATE) (DATABASE|SCHEMA) |SELECT ALL |\.tables|\.quit|\.databases)",
                    "/.psql_history", "^(INSERT INTO |DELETE FROM |(DROP|CREATE) TABLE |(DROP|CREATE) (DATABASE|SCHEMA) |SELECT ALL |GRANT ALL ON )",
                    "/.sh_history", "^(less|more|wget |curl |grep |chmod |chown |iptables|ifconfig|history|touch |head|tail|mkdir |sudo)",
                    "/.bash_history", "^(less|more|wget |curl |grep |chmod |chown |iptables|ifconfig|history|touch |head|tail|mkdir |sudo)",
                    "/.profile", "^# ~/\.profile:",
                    "/.bashrc", "^# ~/\.bashrc:" );

report = 'The following files were identified:\n';

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  foreach file( keys( files ) ) {

    url = dir + file;

    # nb: If required we might use a similar reporting like done in the following VTs:
    # - 2016/sw_scm_files_accessible_http.nasl
    # - 2018/gb_sensitive_file_disclosures_http.nasl
    # nb: If false positives are reported at some point in the future we might want to check for a
    # "Content-Type: text/html" and continue here if this is included.
    if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:files[file], usecache:TRUE ) ) {
      report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      VULN = TRUE;
    }
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
