# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# Protocols (Currently only StreamProtocol used)
RMI_PROTO["STREAM_PROTO"]      = raw_string(0x4b);  # StreamProtocol
RMI_PROTO["SINGLE_OP_PROTO"]   = raw_string(0x4c);  # SingleOpProtocol
RMI_PROTO["MULTIPLEX_PROTO"]   = raw_string(0x4d);  # MultiplexProtocol

# @brief Connects to a RMI service
#
# @param socket The socket to communicate with
#
# @return TRUE in case a connection could be established and the responds with an ProtocolAck, FALSE
#         in case of an error.
#
function rmi_connect(socket) {
  local_var socket;
  local_var magic, version, protocol;
  local_var req, res;
  local_var host, port;

  if (!socket) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#rmi_connect");
    return FALSE;
  }

  magic = "JRMI";
  version = mkword(2);
  protocol = RMI_PROTO["STREAM_PROTO"];

  req = magic + version + protocol;

  send(socket: socket, data: req);
  res = recv(socket: socket, length: 128, min: 7);

  if (!res ||
      hexstr(res[0]) != "4e" ||         # ProtocolAck
      (getword(blob: res, pos: 1) + 7) != strlen(res))
    return FALSE;

  # The client must then respond with another EndpointIdentifier that contains the clients default
  # endpoint for accepting connections.
  host = this_host();
  port = 0;              # nb: Seems to not matter as long as we don't use MultiplexProtocol

  req = mkword(strlen(host)) + host + mkdword(port);

  send(socket: socket, data: req); # nb: We don't expect a response so just send and forget

  return TRUE;
}

# @brief List the named objects in the remote RMI registry
#
# @param socket The socket to communicate with
#
# @return Return the received response
#
function rmi_list(socket) {
  local_var socket;
  local_var req, res;

  if (!socket) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#rmi_list");
    return;
  }

  req = raw_string(0x50,                    # Output Stream Message: Call
                   0xac, 0xed,              # Magic
                   mkword(5),               # Version
                   0x77,                    # TC_BLOCKDATA
                   0x22,                    # Length
                   0x00, 0x00, 0x00, 0x00,  # ObjectID
                   0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00,  # Unique
                   0x00, 0x00, 0x00, 0x00,  # Time
                   0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00,              # Count
                   0x00, 0x00, mkword(1),   # Opcode: 1 list();
                   0x44, 0x15, 0x4d, 0xc9,  # Hash code for sun.rmi.registry.RegistryImpl_Stub
                   0xd4, 0xe6, 0x3b, 0xdf);

  send(socket: socket, data: req);
  res = recv(socket: socket, length: 4096, min: 7);

  return res;
}

# @brief Does a lookup of an object in the Registry
#
# @param socket The socket to communicate with
# @param obj_name The object name we want to do the lookup on
#
# @return
#
function rmi_lookup(socket, obj_name) {
  local_var socket, obj_name;
  local_var req, res;

  if (!socket) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#rmi_lookup");
    return;
  }

  if (!obj_name || strlen(chomp(obj_name)) == 0) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#obj_name#-#rmi_lookup");
    return;
  }

  req = raw_string(0x50,                     # Output Stream Message: Call
                   0xac, 0xed,               # Magic
                   mkword(5),                # Version
                   0x77,                     # TC_BLOCKDATA
                   0x22,                     # Length
                   0x00, 0x00, 0x00, 0x00,   # ObjectID
                   0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00,   # Unique
                   0x00, 0x00, 0x00, 0x00,   # Time
                   0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00,               # Count
                   0x00, 0x00, mkword(2),    # Opcode: 2 lookup();
                   0x44, 0x15, 0x4d, 0xc9,   # Hash code for sun.rmi.registry.RegistryImpl_Stub
                   0xd4, 0xe6, 0x3b, 0xdf,
                   0x74,                     # String type
                   mkword(strlen(obj_name)), # Length of object name
                   obj_name);

  send(socket: socket, data: req);
  res = recv(socket: socket, length: 4096, min: 7);

  return res;
}

# @brief Checks if authentication is needed for a specific object
#
# @param socket The socket to communicate with
# @param objectid The Object ID of the object we want to check
#
# @return TRUE if authentication is needed (Exception returned) or if there is an error or FALSE if
#         no authentication is needed
#
function rmi_need_authentication(socket, objectid) {
  local_var socket, objectid;
  local_var req, res;

  if (!socket) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#rmi_need_authentication");
    return TRUE;
  }

  if (!objectid) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#objectid#-#rmi_need_authentication");
    return TRUE;
  }

  req = raw_string(0x50,                     # Output Stream Message: Call
                   0xac, 0xed,               # Magic
                   mkword(5),                # Version
                   0x77,                     # TC_BLOCKDATA
                   0x22,                     # Length
                   objectid,                 # ObjectID
                   0xff, 0xff, 0xff, 0xff,   # Opcode
                   0xf0, 0xe0, 0x74, 0xea,   # Hash code (currently unknown hash)
                   0xad, 0x0c, 0xae, 0xa8,
                   0x70);

  send(socket: socket, data: req);
  res = recv(socket: socket, length: 4096, min: 7);
  if (!res)
    return TRUE;

  res = bin2string(ddata: res, noprint_replacement: " ");

  # e.g.:
  # java.lang.SecurityException
  # java.lang.RuntimeException
  # java.lang.Exception
  # java.rmi.UnmarshalException
  if (res =~ "java\.(lang|rmi)\.[A-Za-z]*Exception" && "UnicastRef" >!< res)
    return TRUE;

  return FALSE;
}

# @brief Tries to authenticate with the given credentiasl for a specific object
#
# @param socket The socket to communicate with
# @param objectid The Object ID of the object we want to authenticate
# @param username The username to use for authentication
# @param password (optional) The password to use for authentication (default is an empty password)
#
# @return TRUE if authentication was successful or FALSE otherwise
#
function rmi_authenticate(socket, objectid, username, password) {
  local_var socket, objectid, username, password;
  local_var req, res;

  if (!socket) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#rmi_authenticate");
    return FALSE;
  }

  if (!objectid) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#objectid#-#rmi_authenticate");
    return FALSE;
  }

  if (!username) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#username#-#rmi_authenticate");
    return FALSE;
  }

  if (!password)
    password = "";

  req = raw_string(0x50,                     # Output Stream Message: Call
                   0xac, 0xed,               # Magic
                   mkword(5),                # Version
                   0x77,                     # TC_BLOCKDATA
                   0x22,                     # Length
                   objectid,                 # ObjectID
                   0xff, 0xff, 0xff, 0xff,   # Opcode
                   0xf0, 0xe0, 0x74, 0xea,   # Hash code (currently unknown hash)
                   0xad, 0x0c, 0xae, 0xa8,
                   0x75, 0x72, 0x00, 0x13,   # Unknown
                   0x5b, 0x4c,
                   "java.lang.String",
                   0x3b, 0xad, 0xd2, 0x56,   # Unknown
                   0xe7, 0xe9, 0x1d, 0x7b,
                   0x47, 0x02, 0x00, 0x00,
                   0x70, 0x78, 0x70, 0x00,
                   0x00, 0x00, 0x02,
                   0x74,                     # String type
                   mkword(strlen(username)), # username length
                   username,                 # username
                   0x74,                     # String type
                   mkword(strlen(password)), # password length
                   password);

  send(socket: socket, data: req);
  res = recv(socket: socket, length: 4096);

  if (!res)
    return FALSE;

  res = bin2string(ddata: res, noprint_replacement: " ");

  # e.g.:
  # java.lang.SecurityException
  # java.lang.RuntimeException
  # java.lang.Exception
  # java.rmi.UnmarshalException
  if ("UnicastRef" >< res && res !~ "java\.(lang|rmi)\.[A-Za-z]*Exception")
    return TRUE;

  return FALSE;
}
