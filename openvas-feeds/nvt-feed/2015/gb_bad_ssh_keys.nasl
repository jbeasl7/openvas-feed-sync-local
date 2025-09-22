# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105398");
  script_version("2025-08-21T05:40:06+0000");
  # nb: Unlike other VTs we're using the CVEs line by line here for easier addition of new CVEs / to
  #     avoid too large diffs when adding a new CVE.
  script_cve_id("CVE-2012-1493",
                "CVE-2013-0137",
                "CVE-2013-3619",
                "CVE-2014-8428",
                "CVE-2014-125121",
                "CVE-2015-0936",
                "CVE-2016-1561",
                "CVE-2018-16158"
               );
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-21 05:40:06 +0000 (Thu, 21 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-06 21:06:28 +0000 (Tue, 06 Nov 2018)");
  script_tag(name:"creation_date", value:"2015-10-14 11:48:40 +0200 (Wed, 14 Oct 2015)");
  script_name("Static SSH Private Key Used (TCP)");
  script_category(ACT_ATTACK);
  script_family("Gain a shell remotely");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125761/Array-Networks-vxAG-xAPV-Privilege-Escalation.html");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Jan/76");
  script_xref(name:"URL", value:"https://github.com/cmaruti/reports/raw/master/barracuda_load_balancer_vm.pdf");
  script_xref(name:"URL", value:"https://gist.github.com/todb-r7/5d86ecc8118f9eeecc15");
  script_xref(name:"URL", value:"https://blog.rapid7.com/2016/04/07/r7-2016-04-exagrid-backdoor-ssh-keys-and-hardcoded-credentials/");
  script_xref(name:"URL", value:"https://www.trustmatta.com/advisories/MATTA-2012-002.txt");
  script_xref(name:"URL", value:"https://blog.rapid7.com/2012/06/11/scanning-for-vulnerable-f5-bigips-with-metasploit/");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125754/Loadbalancer.org-Enterprise-VA-7.5.2-Static-SSH-Key.html");
  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/662676");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125755/quantum-root.txt");
  script_xref(name:"URL", value:"https://github.com/mitchellh/vagrant/tree/master/keys");
  script_xref(name:"URL", value:"https://blog.rapid7.com/2013/11/06/supermicro-ipmi-firmware-vulnerabilities/");
  script_xref(name:"URL", value:"https://github.com/BrianWGray/msf/blob/master/exploits/linux/ssh/eaton_known_privkey.rb");

  script_tag(name:"summary", value:"The remote host has a known static SSH private key installed.");

  script_tag(name:"vuldetect", value:"Tries to login as a specific user using a known static SSH
  private key.");

  script_tag(name:"impact", value:"A remote attacker can exploit this issue to gain unauthorized
  access to affected devices. Successfully exploiting this issue allows attackers to completely
  compromise the devices.");

  script_tag(name:"affected", value:"The following products / devices are currently checked / known
  to be vulnerable:

  - CVE-2012-1493: F5 BIG-IP version 11.1.0 build 1943.0

  - CVE-2013-0137: Digital Alert Systems DASDEC and Monroe Electronics One-Net E189 Emergency Alert
  System (EAS) devices

  - CVE-2013-3619: Intelligent Platform Management Interface (IPMI) with firmware for Supermicro X9
  generation motherboards before SMT_X9_317 and firmware for Supermicro X8 generation motherboards
  before SMT X8 312

  - CVE-2014-8428: Barracuda Load Balancer - firmware version 5.0.0.015

  - CVE-2015-0936: Ceragon FibeAir IP-10

  - CVE-2016-1561: ExaGrid storage devices running firmware prior to version 4.8 P26

  - CVE-2018-16158: Eaton Power Xpert Meter 4000, 6000, and 8000 devices before 13.4.0.10

  - CVE-2014-125121: Array Networks vxAG 9.2.0.34 and vAPV 8.3.2.17 appliances

  - No CVE: Loadbalancer.org Enterprise VA 7.5.2 and below

  - No CVE: Quantum DXi V1000 2.2.1 and below

  - No CVE: Vagrant base boxes

  Other products / devices and firmware versions might be affected as well.");

  script_tag(name:"solution", value:"Remove the known SSH private key.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if( get_kb_item( "default_credentials/disable_default_account_checks" ) )
  exit( 0 );

include("bad_ssh_keys.inc");
include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );

if( ssh_dont_try_login( port:port ) )
  exit( 0 );

# nb: No need to continue/start if we haven't received any banner...
if( ! ssh_get_serverbanner( port:port ) )
  exit( 0 );

# nb: No ssh_broken_random_login() as we're doing a SSH private key based login here and there is
# already a check for randomly accepted private keys below.

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

loginCheck = ssh_login( socket:soc, login:"root", password:NULL, priv:check_key, passphrase:NULL );
close( soc );

if( loginCheck == 0 )
  exit( 0 ); # nb: Unused key accepted. Stop the test to avoid false positives.

foreach entry( bad_keys ) {

  es = split( entry, sep:":split:", keep:FALSE );
  if( isnull( es[0] ) || isnull( es[1] ) )
    continue;

  if( ! soc = open_sock_tcp( port ) )
    continue;

  user = es[0];
  pkey = es[1];

  login = ssh_login( socket:soc, login:user, password:NULL, priv:pkey, passphrase:NULL );
  close( soc );

  if( login == 0 ) {
    report = 'It was possible to login using username "' + user + '" and the following known SSH private key:\n' + pkey;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
