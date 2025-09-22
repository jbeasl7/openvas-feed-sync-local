# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103239");
  script_version("2025-04-04T05:39:39+0000");
  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-1999-0501",
                "CVE-1999-0502",
                "CVE-1999-0507",
                "CVE-1999-0508",
                "CVE-2005-1379", # nb: From the CVE description: Mandrake Linux installs the mpi user without a password
                "CVE-2006-5288", # nb: From the CVE description: Cisco 2700 Series Wireless Location Appliances before 2.1.34.0 have a default administrator username "root" and password "password"
                "CVE-2009-3710", # nb: From the CVE description: RioRey RIOS 4.6.6 and 4.7.0 uses an undocumented hard-coded username (dbadmin) and password (sq!us3r) for an SSH tunnel
                "CVE-2012-4577", # nb: From the CVE description: The Linux firmware image on (1) Korenix Jetport 5600 series serial-device servers and (2) ORing Industrial DIN-Rail serial-device servers has a hardcoded password of "password" for the root account
                "CVE-2016-1000245", # nb: For Xiongmai: https://securityledger.com/2016/10/shoddy-supply-chain-lurks-behind-mirai-botnet/ shows the credentials
                "CVE-2017-16523", # nb: For MitraStar: https://www.exploit-db.com/exploits/43061 shows that this seems to be an SSH user
                "CVE-2020-29583",
                "CVE-2020-9473", # nb: From the CVE description: S. Siedle & Soehne SG 150-0 Smart Gateway before 1.2.4 has a passwordless ftp ssh user
                "CVE-2021-27797", # See https://pierrekim.github.io/blog/2025-03-31-brocade-switches-10-vulnerabilities.html#default-weak-creds
                "CVE-2023-1944", # nb: This is for "root:root" as seen on https://github.com/kubernetes/minikube/compare/v1.29.0...v1.30.0#diff-7b41e58d929bdb16083790c3500e6f9aa19efb0976e6b65609b60396cd9ceeebL230
                "CVE-2024-22902", # nb: This is for "root:Backup@3R" as seen on https://blog.leakix.net/2024/01/vinchin-backup-rce-chain/#default-ssh-root-credentials-cve-2024-22902
                "CVE-2024-31970", # nb: This is "admin:admin" like seen in the CVE description
                "CVE-2024-46328"
               );
  script_tag(name:"last_modification", value:"2025-04-04 05:39:39 +0000 (Fri, 04 Apr 2025)");
  script_tag(name:"creation_date", value:"2016-11-02 11:47:00 +0100 (Wed, 02 Nov 2016)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-07 17:37:40 +0000 (Wed, 07 Feb 2024)");
  script_name("SSH Brute Force Logins With Default Credentials Reporting");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_ATTACK);
  script_family("Brute force attacks");
  script_dependencies("default_ssh_credentials.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("default_ssh_credentials/started");

  # nb: This VT had a script preference with the id:1, newly added preferences in the future needs
  # to choose id:2 or higher to avoid conflicts with that removed preference still kept in gvmd
  # database.

  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"It was possible to login into the remote SSH server using
  default credentials.");

  script_tag(name:"vuldetect", value:"Reports default credentials detected by the VT
  'SSH Brute Force Logins With Default Credentials' (OID: 1.3.6.1.4.1.25623.1.0.108013).");

  script_tag(name:"insight", value:"As the VT 'SSH Brute Force Logins With Default Credentials'
  (OID: 1.3.6.1.4.1.25623.1.0.108013) might run into a timeout the actual reporting of this
  vulnerability takes place in this VT instead.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to e.g. gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"affected", value:"The following products are known to use the default credentials
  checked by the VT 'SSH Brute Force Logins With Default Credentials' (OID:
  1.3.6.1.4.1.25623.1.0.108013) used for this reporting:

  - CVE-2017-16523: MitraStar GPT-2541GNAC (HGU) 1.00(VNJ0)b1 and DSL-100HN-T1 ES_113WJY0b16 devices

  - CVE-2020-29583: Zyxel Firewall / AP Controller

  - CVE-2020-9473: S. Siedle & Soehne SG 150-0 Smart Gateway before 1.2.4

  - CVE-2021-27797: Brocade Fabric OS

  - CVE-2023-1944: minikube 1.29.0 and probably prior

  - CVE-2024-22902: Vinchin Backup & Recovery

  - CVE-2024-31970: AdTran SRG 834-5 HDC17600021F1 devices (with SmartOS 11.1.1.1) during a window
  of time when the device is being set up

  - CVE-2024-46328: VONETS VAP11G-300 v3.3.23.6.9

  - Various additional products like e.g. Ubiquiti EdgeMax / EdgeRouter, Crestron AM-100 and similar
  for which no CVE was assigned (See 'default_credentials.inc' file on the file system for a full
  list)

  Other products might be affected as well.");

  script_tag(name:"solution", value:"Change the password as soon as possible.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

credentials = get_kb_list( "default_ssh_credentials/" + port + "/credentials" );
if( ! isnull( credentials ) ) {

  report = 'It was possible to login with the following credentials <User>:<Password>\n\n';

  # Sort to not report changes on delta reports if just the order is different
  credentials = sort( credentials );

  foreach credential( credentials ) {
    report += credential + '\n';
    vuln = TRUE;
  }
}

if( vuln ) {
  c = get_kb_item( "default_ssh_credentials/" + port + "/too_many_logins" );
  if( c ) {
    report += '\nRemote host accept more than ' + c + ' logins. This could indicate some error or some "broken" device.\nScanner stops testing for default logins at this point.';
  }
  security_message( port:port, data:chomp( report ) );
  exit( 0 );
}

exit( 99 );
