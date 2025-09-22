# SPDX-FileCopyrightText: 2002-2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

global_var _nntp_func_debug;
_nntp_func_debug = FALSE;

# NNTP protocol is defined by RFC 977
# NNTP message format is defined by RFC 1036 (obsoletes 850); see also RFC 822.

# @brief TODO
#
# @param socket TODO
# @param username TODO
# @param password TODO
#
# @return TODO
#
function nntp_auth(socket, username, password) {

  local_var socket, username, password;
  local_var buff;

  if(!socket) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#nntp_auth");
    return(0);
  }

  # nb: Empty username might be also valid...
  if(isnull(username)) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#username#-#nntp_auth");
    return(0);
  }

  send(socket:socket, data: string("AUTHINFO USER ", username, "\r\n"));
  buff = recv_line(socket:socket, length:2048);
  send(socket:socket, data: string("AUTHINFO PASS ", password, "\r\n"));
  buff = recv_line(socket:socket, length:2048);
  if("502 " >< buff) {
    if( _nntp_func_debug ) display("Bad username/password for NNTP server");
    return(0);
  }
  return(1);
}

# @brief TODO
#
# @param port TODO
# @param username TODO
# @param password TODO
#
# @return TODO
#
function nntp_connect(port, username, password) {

  local_var port, username, password;
  local_var s, buff, a;

  if(!port) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#nntp_connect");
    return(0);
  }

  s = open_sock_tcp(port);
  if(s) {
    buff = recv_line(socket:s, length:2048);
    a = nntp_auth(socket:s, username:username, password:password);
    if(!a) {
      close(s);
      return;
    }
  }
  return(s);
}

# @brief TODO
#
# @param socket TODO
# @param message TODO
#
# @return TODO
#
function nntp_post(socket, message) {

  local_var socket, message;
  local_var buff;

  if(!socket) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#nntp_post");
    return(0);
  }

  send(socket:socket, data:string("POST\r\n"));
  buff = recv_line(socket:socket, length:2048);

  # 340 = Go ahead; 440 = posting prohibited
  if("340 " >< buff) {
    send(socket:socket, data:message);
    buff = recv_line(socket:socket, length:2048);
    if("240 " >< buff)
      return(1);

    if(ereg(pattern:"^4[34][0-9] +.*unwanted distribution .*local", string:buff, icase:TRUE) &&
       ereg(pattern:"Distribution: +local", string:message)) {
      return -1;
    }
  }
  return(0);
}

# @brief TODO
#
# @param id TODO
# @param timeout TODO
# @param port TODO
# @param username TODO
# @param password TODO
#
# @return TODO
#
function nntp_article(id, timeout, port, username, password) {

  local_var id, timeout, port, username, password;
  local_var vtstrings, t, s, buff;

  vtstrings = get_vt_strings();
  for(t = 0; t < timeout; t = t+5) {
    sleep(5);
    s = nntp_connect(port:port, username:username, password:password);
    if(s) {
      send(socket:s, data:string("ARTICLE ", id, "\r\n"));
      buff = recv_line(socket:s, length:2048);
      send(socket:s, data:string("QUIT\r\n"));
      close(s);
      # nb: The X-vtstrings["default"] header is used in nntp_info.nasl
      if(ereg(pattern:"^220 .*X-" + vtstrings["default"] + ":", string:buff))
        return(buff);
    }
  }
  return(0);
}

# @brief TODO
#
# @param str TODO
#
# @return TODO
#
function nntp_make_id(str) {

  local_var str;
  local_var domain, id;

  domain = get_3rdparty_domain();

  # RFC 822 says that should use a full domain name. Some new servers
  # check that the domain part is valid so we use the "example.com" default.
  # We do not check "str", but it should not contain '@' or '>'
  id = string("<", str, ".x", rand(), "@", domain, ">");
  return(id);
}

# @brief TODO
#
# @param default TODO
#
# @return TODO
#
function nntp_get_port(default) {

  local_var default;
  local_var port;

  if(!default)
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#default#-#nntp_get_port");

  port = get_kb_item("Services/nntp");
  if(port)
    default = port;

  # Includes e.g. PJL ports which are printing everything
  # sent to them so exit for such a port here
  if(port_is_marked_fragile(port:default))
    exit(0);

  if(!get_port_state(default))
    exit(0);

  return default;
}
