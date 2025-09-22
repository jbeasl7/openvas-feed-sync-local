# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105939");
  script_version("2024-07-04T05:05:37+0000");
  script_tag(name:"last_modification", value:"2024-07-04 05:05:37 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-01-21 09:55:57 +0700 (Wed, 21 Jan 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2014-8272");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dell iDRAC Weak SessionID Vulnerability (IPMI Protocol) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ipmi_detect.nasl", "gb_ipmi_default_pw.nasl");
  script_require_udp_ports("Services/udp/ipmi", 623);
  script_mandatory_keys("ipmi/credentials", "ipmi/version/1.5");

  script_tag(name:"summary", value:"Intelligent Platform Management Interface (IPMI) v1.5
  SessionID's are not randomized sufficiently across different channels.");

  script_tag(name:"vuldetect", value:"Checks randomness of the session ID's by activating
  sessions.

  Note: Default credentials needs to be found / available previously for a successful detection of
  this flaw.");

  script_tag(name:"insight", value:"Dell iDRAC6 and iDRAC7 does not properly randomize session ID
  values, which makes it easier for remote attackers to execute arbitrary commands via a
  brute-force attack.");

  script_tag(name:"impact", value:"A remote attacker might be able to execute arbitrary commands
  via a brute-force attack.");

  script_tag(name:"affected", value:"Dell iDRAC6 modular before 3.65, iDRAC6 monolithic before 1.98
  and iDRAC7 before 1.57.57. Other models / vendors might be affected as well.");

  script_tag(name:"solution", value:"- Updates from Dell are available which will disable IPMI v1.5.

  - As a workaround disable IPMI v1.5. Please contact the vendor / consult the device manual for
  more information.");

  script_xref(name:"URL", value:"https://web.archive.org/web/20150618103158/https://labs.mwrinfosecurity.com/blog/2015/01/08/cve-2014-8272/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20201108110204/https://labs.f-secure.com/archive/cve-2014-8272/");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210122092256/https://www.securityfocus.com/bid/71750/");
  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/alerts/2013/07/26/risks-using-intelligent-platform-management-interface-ipmi");
  script_xref(name:"URL", value:"http://fish2.com/ipmi/");

  exit(0);
}

include("dump.inc");
include("byte_func.inc");
include("http_func.inc");
include("ipmi_func.inc");
include("port_service_func.inc");
include("host_details.inc");

debug = FALSE;

port = service_get_port(default: 623, ipproto: "udp", proto: "ipmi");

if (!get_kb_item("ipmi/" + port + "/version/1.5"))
  exit(0);

if (!creds = get_kb_item("ipmi/" + port + "/credentials"))
  exit(0);

if (!soc = open_sock_udp(port))
  exit(0);

getChannelAuthCap = ipmi_v1_5_create_get_channel_auth_cap(debug: debug);
send(socket: soc, data: getChannelAuthCap);

if (!recv = recv(socket: soc, length: 1024)) {
  close(soc);
  exit(0);
}

if (debug) display('IPMI v1.5 Get Channel Authentication Capabilities Response:\n' + hexdump(ddata: recv));

auth_support = dec2bin(dec: ord(recv[22]));

if (auth_support[5] == 1) {
  authAlg = IPMI_1_5_AUTHENTICATION_ALG_MD5;
  authType = IPMI_1_5_AUTHENTICATION_TYPE_MD5;
}
else if (auth_support[3] == 1) {
  authAlg = IPMI_1_5_AUTHENTICATION_ALG_PW;
  authType = IPMI_1_5_AUTHENTICATION_TYPE_PW;
}
else {
  close(soc);
  exit(0); # No suitable authentication algorithm so just exit
}

creds = split(creds, sep: "/", keep: FALSE);
username = creds[0];
password = creds[1];

for (j = 0; j < 10; j++) {
  paddedUsername = username;
  while (strlen(paddedUsername) < 16) { # nb: Password needs to be padded to 16 bytes
    paddedUsername = paddedUsername + raw_string(0x00);
  }

  getSessChallenge = ipmi_v1_5_create_get_session_challenge(auth_type: authType, username: paddedUsername,
                                                            debug: debug);
  if (isnull(getSessChallenge))
    break;

  send(socket:soc, data: getSessChallenge);
  recv = recv(socket:soc, length:1024);

  if (debug) display('IPMI v1.5 Get Session Challenge Response:\n' + hexdump(ddata: recv));

  # Error Checking
  if (!recv || hexstr(recv[20]) != "00")
    break;

  tmp_sessionID = substr(recv, 21, 24);
  challenge = substr(recv, 25, 40);

  activateSession = ipmi_v1_5_create_activate_session_request(auth_type: authType, auth_alg: authAlg,
                                                              challenge: challenge, password: password,
                                                              session_id: tmp_sessionID, debug: debug);
  if (isnull(activateSession))
    break;

  send(socket: soc, data: activateSession);
  recv = recv(socket: soc, length: 1024);

  if (debug) display('IPMI v1.5 Activate Session Response:\n' + hexdump(ddata: recv));

  # Error checking
  if (!recv)
    continue;

  if (strlen(recv) > 41 && hexstr(recv[36]) == "00") {
    sessionid = substr(recv, 38, 41);
    sessionids[j] = raw_string(hexstr(sessionid[3]), hexstr(sessionid[2]), hexstr(sessionid[1]),
                               hexstr(sessionid[0]));
  } else {
    continue;
  }

  # Close the session (some devices have very limited session slots available)
  closeSession = ipmi_v1_5_create_close_session_request(auth_type: authType, auth_alg: authAlg,
                                                        password: password, session_id: sessionid,
                                                        debug: debug);
  if (isnull(closeSession))
    break;

  send(socket: soc, data: closeSession);
  recv = recv(socket: soc, length: 1024);
  if (debug) display('IPMI v1.5 Close Session Response:\n' + hexdump(ddata: recv));
}

close(soc);

const_diff = 0;
for (i = 1; i < 10; i++) {
  id1 = hex2dec(xvalue: sessionids[i - 1]);
  id2 = hex2dec(xvalue: sessionids[i]);
  if (id1 < id2) {
    const_diff = id2 - id1;
    break;
  }
}

if (const_diff > 0) {
  vulnerable = TRUE;
  notmatched = 0;

  for (i = 1; i < 10; i++) {
    if (hex2dec(xvalue: sessionids[i]) - hex2dec(xvalue: sessionids[i - 1]) != const_diff) {
      if (notmatched < 2)
        notmatched++;
      else
        vulnerable = FALSE;
    }

    ids += hex2dec(xvalue: sessionids[i]) + '\n';
  }
}

if (vulnerable) {

  # nb:
  # - Store the reference from this one to gb_ipmi_detect.nasl to show a cross-reference within the
  #   reports
  # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
  register_host_detail(name: "detected_by", value: "1.3.6.1.4.1.25623.1.0.103835"); # gb_ipmi_detect.nasl
  register_host_detail(name: "detected_at", value: port + "/udp");

  report = "The randomness of the session ID is not sufficiently randomized." +
           '\n\nSession IDs:\n\n' + chomp(ids);
  security_message(port: port, data: report, proto: "udp");
  exit(0);
}

exit(99);
