# SPDX-FileCopyrightText: 2004 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14272");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("Netstat 'scanner'");
  # nb: This has been placed into ACT_SETTINGS instead of ACT_SCANNER or ACT_GATHER_INFO for the
  # following reasons:
  # - The VT needs to run before find_service.nasl so that this VT (and any follow-up ones) could
  #   use possible additional found open ports
  # - It wasn't placed into ACT_SCANNER because the netstat service and SSH login-based detections
  #   rely on a previously running "real" port scanner like e.g. nmap.nasl
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2004 Michel Arboi");
  script_family("Port scanners");
  script_dependencies("ssh_authorization_init.nasl", "toolcheck.nasl");

  script_tag(name:"summary", value:"This plugin runs netstat to find open ports:

  - on the local machine by running the command

  - via SSH by using the provided credentials

  - by querying a possible exposed netstat service");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("port_service_func.inc");

bin_available = get_kb_item("Tools/Present/netstat");

if (kb_ssh_login() && (kb_ssh_password() || kb_ssh_privatekey()))
  ssh_creds_available = TRUE;

# On the local machine, just run the command but only if "netstat" is available
if (islocalhost() && bin_available)
  buf = pread(cmd: "netstat", argv: make_list("netstat", "-a", "-n"));
else
{
  # First try the netstat service, just in case
  netstatPorts = service_get_ports(proto: "netstat", default_port_list: make_list(15));

  foreach netstatPort (netstatPorts)
  {
    s = open_sock_tcp(netstatPort);
    if (s)
    {
      while (r = recv(socket: s, length: 4096))
        buf += r;
      close(s);
      break;
    }
  }

  # Then try SSH if the result is not OK...
  if ("LISTEN" >!< buf)
  {

    # ... but only if the user has given SSH credentials. We can exit early here because there are
    # no further checks done down below besides the SSH ones which can't work without given creds.
    if (! ssh_creds_available)
      exit(0);

    port = kb_ssh_transport();
    if (port && get_port_state(port))
    {
      sock = ssh_login_or_reuse_connection();
      if (sock)
      {
        buf = ssh_cmd(socket: sock, cmd: "cmd /c netstat -an", timeout: 60);

        if ("LISTENING" >!< buf && "0.0.0.0:0" >!< buf && "*.*" >!< buf)
        {
          buf = ssh_cmd(socket: sock, cmd: "netstat -a -n", timeout: 60);
          ssh_close_connection();
          if (! buf || "LISTENING" >!< buf)
            exit(0);
        } else {
          ssh_close_connection();
        }
      }
    }
  }
}

ip = get_host_ip();
lines = split(buf);
n = max_index(lines);
if (n == 0) n = 1; i = 0;
scanner_status(current: 0, total: n);
scanned = 0;
last_seen_proto = "";
check =
 (! safe_checks()) ||
 ("yes" >< get_preference("unscanned_closed"));

identd_n = 0; identd_err = 0;

foreach line (lines)
{
  v = eregmatch(pattern: '^[ \t]+(TCP|UDP)[ \t]+([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+):([0-9]+)[ \t]+(0\\.0\\.0\\.0:0|\\*\\.\\*)[ \t]+', string: line, icase: 0);
  # Unix
  if (isnull(v))
    v = eregmatch(pattern: '^(tcp|udp)[46]?[ \t]+.*[ \t]+(\\*|[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+)[:.]([0-9]+)[ \t]+(.*[ \t]+LISTEN|0\\.0\\.0\\.0:\\*)', string: line, icase: 1);
  if (isnull(v))
  # tcp 0 0 :::22   :::*    LISTEN
  # tcp 0 0 ::1:25  :::*    LISTEN (1 = localhost)
  v = eregmatch(pattern: '^(tcp|udp)[ \t]+.*[ \t]+(:::)([0-9]+)[ \t]+.*[ \t]+LISTEN', string: line, icase: 1);

  # Solaris 9
  if (isnull(v))
  {
    if (last_seen_proto)
    {
      if (last_seen_proto == 'udp')
        v = eregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+Idle', string: line);
      else
        v = eregmatch(pattern: '^[ \t]*(\\*|[0-9.]+)\\.([0-9]+)[ \t]+\\*\\.\\*[ \t]+.*(Idle|LISTEN)', string: line);

      if (! isnull(v))
      {
        # "Fix" array
        v[3] = v[2]; v[2] = v[1]; v[1] = last_seen_proto;
      }
    }
    if (isnull(v))
    {
      v = eregmatch(pattern: '^(TCP|UDP): +IPv4[ \t\r\n]*$', string: line);
      if (!isnull(v))
      {
        last_seen_proto = tolower(v[1]);
        v = NULL;
      }
    }
  }


  if (!isnull(v))
  {
    if (check)
      identd_soc = open_sock_tcp(113);
    proto = tolower(v[1]);
    addr = v[2];
    port = v[3];
    # display("> ", addr, ":", port, " (", proto, ")\n");
    if (int(port) < 1 || int(port) > 65535) {
      #display('netstat_portscan(', get_host_ip(), '): invalid port number ', port, '\n');
    } else if ((check && addr != "127.0.0.1") ||
      addr == "0.0.0.0" || addr == ip || addr == ":::" || addr == '*')
    {
      if (check && proto == "tcp")
      {
        soc = open_sock_tcp(port);
        if (soc)
        {
          scanner_add_port(proto: proto, port: port);
          if (identd_soc)
          {
            req = strcat(port, ',', get_source_port(soc), '\r\n');
            if (send(socket: identd_soc, data: req) <= 0)
            {
              # Let's be quick: do not reopen the socket if an error occurs
              # Another plugin with complete the job
              close(identd_soc);
              identd_soc = NULL;
              identd_err ++;
              id = NULL;
            }
            else
              id = recv_line(socket: identd_soc, length: 1024);
            if (id)
            {
              ids = split(id, sep: ':');
              if (ids && "USERID" >< ids[1])
              {
                identd_n++;
                set_kb_item(name: "ident/tcp/" + port, value: ids[3]);
                log_message(port: port, data: 'identd reveals that this service is running as user ' + ids[3]);
              }
            }
          }
          close(soc);
        }
      }
      else
      scanner_add_port(proto: proto, port: port);
      # display(proto, "\t", port, "\n");
    }
    scanned ++;
  }
  scanner_status(current: i++, total: n);
}

if (identd_soc) close(identd_soc);

if (scanned)
{
  set_kb_item(name: "Host/scanned", value: TRUE);
  set_kb_item(name: "Host/udp_scanned", value: TRUE);
  set_kb_item(name: "Host/full_scan", value: TRUE);
  set_kb_item(name: 'Host/scanners/netstat', value: TRUE);
  if (identd_n && ! identd_err)
    set_kb_item(name: "Host/ident_scanned", value: TRUE);
}

scanner_status(current: n, total: n);
exit(0);
