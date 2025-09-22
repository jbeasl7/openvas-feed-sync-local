# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105923");
  script_version("2025-03-20T05:38:32+0000");
  script_tag(name:"last_modification", value:"2025-03-20 05:38:32 +0000 (Thu, 20 Mar 2025)");
  script_tag(name:"creation_date", value:"2014-10-29 11:12:02 +0700 (Wed, 29 Oct 2014)");
  # nb: A higher score than the attached CVE-2019-4169 is used here as the found account might have
  # not only partly write (C:P/I:P) but full write access (C:P/I:C).
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:N");

  script_cve_id("CVE-2019-4169");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("IPMI Default Credentials (IPMI Protocol) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Default Accounts");
  script_dependencies("gb_ipmi_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_udp_ports("Services/udp/ipmi", 623);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"It was possible to find default password/username combinations
  for the Intelligent Platform Management Interface (IPMI) protocol.");

  script_tag(name:"vuldetect", value:"Tries to get a RAKP Message 2 (IPMI v2.0) to check the
  password hash or activate a session (IPMI v1.5).");

  script_tag(name:"insight", value:"Many IPMI enabled devices have set default username/password
  combinations. If these are not changed or disabled if opens up an easy exploitable
  vulnerability.");

  script_tag(name:"impact", value:"An attacker can log into the IPMI enabled device often with
  privileged permissions and gain access to the host operating system.");

  script_tag(name:"affected", value:"All IPMI devices providing/using default credentials. The
  following is an excerpt of known tested credentials:

  - No CVEs: Dell iDRAC, SuperMicro BMC, IBM IMM, Fujitsu IRMC, Oracle/Sun ILOM, Asus IKVM BMC

  - CVE-2019-4169: IBM Open Power Firmware / OpenBMC

  Other devices / vendors might be affected as well.");

  script_tag(name:"solution", value:"- Change the default passwords or disable the default accounts
  if possible

  - Filter traffic to UDP port 623

  Please contact the vendor / consult the device manual for more information.");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/105730/Supermicro-IPMI-Default-Accounts.html");
  script_xref(name:"URL", value:"https://github.com/netbiosX/Default-Credentials/blob/master/IPMI-Default-Password-List.mdown");
  script_xref(name:"URL", value:"https://support.siliconmechanics.com/portal/en/kb/articles/default-ipmi-credentials");
  script_xref(name:"URL", value:"https://hyperhci.com/2019/11/16/nutanix-cvm-ahv-ipmi-default-credentials/");
  script_xref(name:"URL", value:"https://docs.netgate.com/pfsense/en/latest/solutions/xg-1537/ipmi-access.html");
  script_xref(name:"URL", value:"https://docs.netapp.com/us-en/element-software/storage/task_post_deploy_credential_change_ipmi_password.html");
  script_xref(name:"URL", value:"https://support.exinda.gfi.com/hc/en-us/articles/360015166720-Default-IPMI-Credentials");
  script_xref(name:"URL", value:"https://www.cisa.gov/news-events/alerts/2013/07/26/risks-using-intelligent-platform-management-interface-ipmi");
  script_xref(name:"URL", value:"http://fish2.com/ipmi/");
  script_xref(name:"URL", value:"https://www.ibm.com/docs/en/power9/8335-GTC?topic=gui-logging-openbmc");
  script_xref(name:"URL", value:"https://www.ibm.com/support/pages/security-bulletin-power-system-update-being-released-address-cve-2019-4169");
  script_xref(name:"URL", value:"https://www.servethehome.com/openbmc-default-login-credentials-and-root-password/");
  script_xref(name:"URL", value:"https://www.rapid7.com/blog/post/2013/07/02/a-penetration-testers-guide-to-ipmi/");

  exit(0);
}

if (get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("dump.inc");
include("misc_func.inc");
include("byte_func.inc");
include("ipmi_func.inc");
include("port_service_func.inc");
include("host_details.inc");

debug = FALSE;

function verify_sha1_hash(password, salt, sha1) {
  local_var password, salt, sha1;
  local_var hmac;

  hmac = HMAC_SHA1(data: salt, key: password);
  return (hmac == sha1);
}

function create_rakp_salt(sid, bmcsid, randid, bmcrandid, bmcguid, username) {
  local_var sid, bmcsid, randid, bmcrandid, bmcguid, username;
  local_var salt;

  salt = raw_string(mkdword(sid), mkdword(bmcsid), randid, bmcrandid, bmcguid, 0x14, strlen(username), username);
  return salt;
}

port = service_get_port(default: 623, ipproto: "udp", proto: "ipmi");

if (!soc = open_sock_udp(port))
  exit(0);

# nb:
# - If additional usernames are added here please make sure to add them to:
#   gsf/2023/gb_ipmi_rakp_vuln_jul13_active.nasl as well
# - If additional usernames or passwords are added here please make sure to add them:
#   gsf/2024/gb_redfish_api_http_default_credentials.nasl
#   as it seems that the devices are sharing the same credentials for IMPI and Redfish
# - Unlike for Redfish the "root:calvin" seems to be completely lowercase (Redfish seems to have
#   uppercase first letters)
# - Credentials taken from various sources, like e.g.:
#   - linked in the references above
#   - from e.g. http://fish2.com/ipmi/itrain.pdf (page 20)
#   - own research in e.g. the manual of Redfish enabled systems / devices which seems to share the
#     same credentials with IPMI systems (See gsf/2024/gb_redfish_api_http_default_credentials.nasl
#     for the relevant links)
# - For Avid systems the creds are "admin:admin", "admin:Avid123" or "avid:Avid123"
# - TBD: We might want to change this into an "array" in the future that only known username/password pairs are checked
usernames = make_list("", "ADMIN", "admin", "root", "USERID", "Administrator", "guest", "Admin", "administrator", "sysadmin", "avid");
passwords = make_list("admin", "calvin", "PASSW0RD", "ADMIN", "changeme", "password", "superuser", "test", "0penBmc", "root", "computer1", "4rfv$RFV", "123456", "Admin@9000", "DefaultFactoryPassword", "advantech", "Huawei12#$", "P@ssw0rd", "p@ssw0rd", "Avid123");

# IPMI v2.0
if (get_kb_item("ipmi/" + port + "/version/2.0")) {
  foreach username (usernames) {
    # Open Session Request
    console_session_id = rand();

    open_req = ipmi_v2_create_open_session_request(console_session_id: console_session_id, debug: debug);
    if (isnull(open_req))
      continue;

    send(socket: soc, data: open_req);
    recv = recv(socket: soc, length: 1024);

    # Error Checking
    if (!recv || hexstr(recv) !~ "0600ff070611") {
      close(soc);
      exit(0);                          # Not the right response, so exit
    }

    if (hexstr(recv[17]) == "01") {     # Try to handle "Insufficient Resources"
      sleep(3);
      continue;
    }

    bmc_session_id = ipmi_v2_parse_open_session_reply(data: recv, debug: debug);
    if (isnull(bmc_session_id))
      continue;

    console_random_id = rand_str(length: 16, charset: "0123456789");

    # RAKP Message 1
    rakp_1 = ipmi_v2_create_rakp_message_1(bmc_session_id: bmc_session_id, console_id: console_random_id,
                                           username: username, debug: debug);
    if (isnull(rakp_1))
      continue;

    send(socket: soc, data: rakp_1);
    recv = recv(socket: soc, length: 1024);

    # Error Checking
    if (!recv || hexstr(recv[16]) !~ "00" || hexstr(recv[17]) !~ "00") {
      continue;
    }
    else {
      if (!infos = ipmi_v2_parse_rakp_message_reply(data: recv, debug: debug))
        continue;

      sha1_hash = infos["hash"];
      bmc_random_id = infos["rand_bmc_id"];
      bmc_guid = infos["bmc_guid"];

      foreach password (passwords) {
        salt = create_rakp_salt(sid: console_session_id, bmcsid: bmc_session_id, randid: console_random_id,
                                bmcrandid: bmc_random_id, bmcguid: bmc_guid, username: username);

        if (verify_sha1_hash(password: password, salt: salt, sha1: sha1_hash)) {
          set_kb_item(name: "ipmi/credentials", value: TRUE);
          set_kb_item(name: "ipmi/" + port + "/credentials", value: username + "/" + password);
          if (username == "") {
            username = "<blank>";
          }
          report += username + "/" + password + "\n";
          break;
        }
      }
    }
  }
}
# IPMI v1.5
else {
  getChannelAuthCap = ipmi_v1_5_create_get_channel_auth_cap(debug: debug);

  send(socket: soc, data: getChannelAuthCap);
  recv = recv(socket: soc, length: 1024);
  if (!recv) {
    close(soc);
    exit(0);
  }

  if (debug) display('IPMI v1.5 Get Channel Authentication Capabilities Response:\n' + hexdump(ddata: recv));

  auth_support = dec2bin(dec: ord(recv[22]));
  if (debug) display("Authentication Support Flags:  " + auth_support);

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

  foreach username (usernames) {
    paddedUsername = username;
    while (strlen(paddedUsername) < 16) # nb: Password needs to be padded to 16 bytes
      paddedUsername = paddedUsername + raw_string(0x00);

    foreach password (passwords) {
      getSessChallenge = ipmi_v1_5_create_get_session_challenge(auth_type: authType, username: paddedUsername,
                                                                debug: debug);
      if (isnull(getSessChallenge))
        continue;

      send(socket: soc, data: getSessChallenge);
      recv = recv(socket: soc, length: 1024);

      if (debug) display('IPMI v1.5 Get Session Challenge Response:\n' + hexdump(ddata: recv));

      # Error Checking
      if (!recv || hexstr(recv[20]) != "00")
        break;

      sessionID = substr(recv, 21, 24);
      challenge = substr(recv, 25, 40);

      activateSession = ipmi_v1_5_create_activate_session_request(auth_type: authType, auth_alg: authAlg,
                                                                  challenge: challenge, password: password,
                                                                  session_id: sessionID, debug: debug);
      if (isnull(activateSession))
        continue;

      send(socket: soc, data: activateSession);
      recv = recv(socket: soc, length: 1024);

      # Error checking
      if (!recv)
        continue;

      if (debug) display('IPMI v1.5 Activate Session Response:\n' + hexdump(ddata: recv));

      if (strlen(recv) > 36 && hexstr(recv[36]) == "00") {
        set_kb_item(name: "ipmi/credentials", value: TRUE);
        set_kb_item(name: "ipmi/" + port + "/credentials", value: username + "/" + password);
        if (username == "")
          username = "<blank>";

        report += username + "/" + password + "\n";

        # Close the session (some devices have very limited session slots available)
        sessionid = substr(recv, 38, 41);
        closeSession = ipmi_v1_5_create_close_session_request(auth_type: authType, auth_alg: authAlg,
                                                              password: password, session_id: sessionid,
                                                              debug: debug);
        if (isnull(closeSession))
          break;

        send(socket: soc, data: closeSession);
        break;
      }
    }
  }
}

close(soc);

if (report) {

  # nb:
  # - Store the reference from this one to gb_ipmi_detect.nasl to show a cross-reference within the
  #   reports
  # - We don't want to use get_app_* functions as we're only interested in the cross-reference here
  register_host_detail(name: "detected_by", value: "1.3.6.1.4.1.25623.1.0.103835"); # gb_ipmi_detect.nasl
  register_host_detail(name: "detected_at", value: port + "/udp");

  report = string('Found the following default Username/Password combination:\n\n', report);
  security_message(port: port, proto: "udp", data: chomp(report));
  exit(0);
}

exit(99);
