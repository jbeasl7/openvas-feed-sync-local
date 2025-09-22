# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114448");
  script_version("2025-07-30T05:45:23+0000");
  script_tag(name:"last_modification", value:"2025-07-30 05:45:23 +0000 (Wed, 30 Jul 2025)");
  script_tag(name:"creation_date", value:"2024-03-18 14:00:04 +0000 (Mon, 18 Mar 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NETCONF Protocol / Subsystem over SSH Detection (SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Service detection");
  # nb: ssh_detect.nasl so that "service_register()" used below doesn't cause trouble for that
  # detection.
  script_dependencies("ssh_authorization.nasl", "global_settings.nasl", "ssh_detect.nasl");
  script_require_ports(830);
  script_mandatory_keys("login/SSH/success");

  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc6242");
  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc6241");
  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#creating-a-target");
  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-22.04/en/scanning.html#credentials");

  script_tag(name:"summary", value:"SSH login-based detection of services supporting the NETCONF
  protocol / subsystem over SSH.");

  script_tag(name:"vuldetect", value:"Logs into the target via SSH and checks if the NETCONF
  protocol is available / subsystem can be requested.

  Note: Valid SSH credentials needs to be provided in the target configuration for a successful
  detection. Please see the references for more information.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

SCRIPT_NAME = "NETCONF Protocol / Subsystem over SSH Detection (SSH Login)";
debug_enabled = get_kb_item( "global_settings/ssh/debug" );

# nb: Available since openvas-scanner 23.0.0 / https://github.com/greenbone/openvas-scanner/pull/1594
if( ! defined_func( "ssh_execute_netconf_subsystem" ) ) {
  if( debug_enabled ) log_message( port:0, data:"** " + SCRIPT_NAME + " DEBUG **: Required 'ssh_execute_netconf_subsystem' function not provided by the scanner (scanner too old?)." );
  exit( 0 );
}

include("ssh_func.inc");
include("port_service_func.inc");
include("host_details.inc");

login      = kb_ssh_login();
password   = kb_ssh_password();
privkey    = kb_ssh_privatekey();
passphrase = kb_ssh_passphrase();

# nb: Shouldn't happen but just to make sure...
if( ! login && ( ! password && ! privkey ) ) {
  if( debug_enabled ) log_message( port:0, data:"** " + SCRIPT_NAME + " DEBUG **: Required SSH credentials are missing / not provided in the target configuration." );
  exit( 0 );
}

# nb: Only the default 830/tcp for now...
port = 830;
if( ! get_port_state( port ) ) {
  if( debug_enabled ) log_message( port:port, data:"** " + SCRIPT_NAME + " DEBUG **: No open port identified." );
  exit( 0 );
}

soc = open_sock_tcp( port );
if( ! soc ) {
  if( debug_enabled ) log_message( port:port, data:"** " + SCRIPT_NAME + " DEBUG **: open_sock_tcp(): Scanner failed to open a TCP connection to the remote SSH service." );
  exit( 0 );
}

sess = ssh_connect( socket:soc );
if( ! sess ) {
  if( debug_enabled ) log_message( port:port, data:"** " + SCRIPT_NAME + " DEBUG **: ssh_connect(): Scanner failed to setup an SSH session to the remote SSH service." );
  close( soc );
  exit( 0 );
}

auth_successful = ssh_userauth( sess, login:login, password:password, privatekey:privkey, passphrase:passphrase );

# nb: ssh_userauth() is returning 0 on success but everything else like -1, 1 or NULL is an error
# or failure.
if( isnull( auth_successful ) || auth_successful ) {
  if( isnull( auth_successful ) )
    reason = "NULL (failure during SSH session ID verification)";
  else
    reason = auth_successful + " (libssh error code)";
  if( debug_enabled ) log_message( port:port, data:"** " + SCRIPT_NAME + " DEBUG **: ssh_userauth(): Scanner failed to authenticate against the remote SSH service. Reason: " + reason );

  ssh_disconnect( sess );
  close( soc );
  exit( 0 );
}

netconf_sess = ssh_execute_netconf_subsystem( sess );

# nb: From the function description:
# > An int on success or NULL on error.
# The function seems to either return a valid session ID or some error code if e.g. ssh_channel_open_session() failed
if( isnull( netconf_sess ) ) {
  if( debug_enabled ) log_message( port:port, data:"** " + SCRIPT_NAME + " DEBUG **: ssh_execute_netconf_subsystem(): Scanner is unable to execute the NETCONF subsystem on the remote SSH service. Reason: NULL (failure during SSH session ID verification or unable to open a channel)" );
} else {

  # nb: So that we're not overriding the previous valid "sess" as we would pass a possible NULL
  # value to the "ssh_disconnect()" below otherwise.
  sess = netconf_sess;

  banner = ssh_read_from_shell( sess:sess, timeout:30, retry:10 );
  banner = chomp( banner );

  # nb:
  # - We're not setting things like "ssh/no_linux_shell" because this would set these for the whole
  #   host while on e.g. 22/tcp a standard shell could be available...
  # - See e.g. these for some examples:
  #   - https://datatracker.ietf.org/doc/html/rfc6242#page-4
  #   - https://www.juniper.net/documentation/us/en/software/junos/netconf/topics/task/netconf-session-starting.html
  #
  # - Juniper Junos OS seems to also start their response with something like shown below so the
  #   initial "hello" regex below had to be made a little bit less strict.
  #
  #   <!-- No zombies were killed during the creation of this user interface -->
  #   <!-- user root, class super-user -->
  #   <hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
  #   *snip*
  #
  # - "]]>]]>" is the end of the command and might be included in responses at the end. But the
  #   following:
  #
  #   https://subscription.packtpub.com/book/cloud-and-networking/9781788290999/1/ch01lvl1sec03/junos-netconf-over-ssh-setup
  #
  #   says the following below so this isn't checked here (at least currently):
  #
  #   > Technically, this framing sequence is actually deprecated within the latest specification of
  #   > the NETCONF-over-SSH standard, because it was discovered that it can legitimately appear
  #   > within the XML payload. The JUNOS OS implementation currently makes use of the framing
  #   > sequence to flag the end of its responses, but if you write software -- as we will -- to
  #   > read the NETCONF XML stream directly, then it is wise to be aware that this behavior could
  #   > change in the future.
  #
  if( banner && "netconf" >< banner &&
      banner =~ "<hello[^>]*>.*<capabilities>.*<capability>.*</capability>.*</capabilities>.*</hello>" ) {

    message = "An SSH service supporting the NETCONF protocol / subsystem seems to be running on this port";
    report = message + '. The following NETCONF <hello> "banner" has been received:\n\n' + banner;

    log_message( port:port, data:report );
    service_register( port:port, proto:"netconf-ssh", message:message );

    set_kb_item( name:"netconf/ssh/detected", value:TRUE );
    set_kb_item( name:"netconf/ssh/" + port + "/detected", value:TRUE );
    set_kb_item( name:"netconf/ssh/" + port + "/hello_banner", value:banner );

    # nb: Close the connection "gracefully"
    close_req = '<rpc message-id="101"';
    close_req += ' xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">\n';
    close_req += '  <close-session/>\n';
    close_req += '</rpc>\n';
    close_req += ']]>]]>';

    ssh_shell_write( sess, cmd:close_req );
  }

  else if( banner ) {
    if( debug_enabled ) log_message( port:port, data:"** " + SCRIPT_NAME + ' DEBUG **: ssh_shell_read(): Scanner received unknown response:\n\n' + banner );
  }

  else {
    if( debug_enabled ) log_message( port:port, data:"** " + SCRIPT_NAME + " DEBUG **: ssh_shell_read(): Scanner received no / empty response." );
  }
}

ssh_disconnect( sess );
close( soc );

exit( 0 );
