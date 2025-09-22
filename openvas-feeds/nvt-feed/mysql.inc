# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

global_var ER_HOST_IS_BLOCKED, ER_HOST_NOT_PRIVILEGED;

# https://dev.mysql.com/doc/refman/5.7/en/error-messages-server.html
ER_HOST_IS_BLOCKED = 1129;
ER_HOST_NOT_PRIVILEGED = 1130;

# @brief Fulfills the initial MySQL handshake (connect and receive the server greeting)
#
# @param soc The existing socket
#
# @return The response from the server
#
function mysql_recv_server_handshake(socket) {

  local_var socket;
  local_var buf, plen;

  if (!socket) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#mysql_recv_server_handshake");
    exit(0);
  }

  buf = recv(socket: socket, length: 4);
  if (!buf || strlen(buf) != 4) {
    close(socket);
    exit(0);
  }

  # - https://web.archive.org/web/20210614014328/https://dev.mysql.com/doc/internals/en/client-server-protocol.html
  # - https://web.archive.org/web/20210506172939/https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::HandshakeV9
  # - https://dev.mysql.com/doc/dev/mysql-server/latest/PAGE_PROTOCOL.html
  # - https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v9.html
  # - https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
  #
  # nb:
  # - Packet Length seems to be 4 (checked above) for protocol version 9 and below
  # - With protocol version 10 it might be longer
  plen = ord(buf[0]) + (ord(buf[1]) / 8) + (ord(buf[2]) / 16);

  # The first packet of a client query will have Packet Number = 0
  # but some servers are also sending a Packet Number of 1 (currently unknown why).
  if (ord(buf[3]) != 0 && ord(buf[3]) != 1) {
    close(socket);
    exit(0);
  }

  buf = recv(socket: socket, length: plen);
  if (strlen(buf) != plen) {
    close(socket);
    exit(0);
  }
  return buf;
}

# @brief Creates a MySQL request and sends it to the server
#
# @param socket The existing socket to send the data to
# @param data   The data which should be sent in a MySQL
# @param seq_id The MySQL Sequence ID (packet number), default = 1
#
# @return Length of the data sent
#
function mysql_send_packet(socket, data, seq_id) {

  local_var socket, data, seq_id;
  local_var len, packet;

  if (!socket) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#mysql_send_packet");
    exit(0);
  }

  if (isnull(data)) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#mysql_send_packet");
    close(socket);
    exit(0);
  }

  # Sequence ID might be 1 if we start with a conversation.
  if (isnull(seq_id))
    seq_id = 1;

  len = strlen(data);

  packet = raw_string(len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff) + mkbyte(seq_id) + data;

  send(socket: socket, data: packet);

  return len + 4;
}

# @brief Receives a MySQL packet and makes a first dissection
#
# @param socket The existing socket to receive data from
#
# @return An array containing received packet length, sequence id, if it contains an error, error number, and the
#         packet itself. NULL if no or a wrong packet was received or another network error occurred. The array
#         indices are the following:
#
#         ret_arr["pkt_len"]   = length of the received packet
#         ret_arr["pkt_seqid"] = received sequence id
#         ret_arr["data"]      = data part in the packet
#         ret_arr["err"]       = TRUE error is indicated, FALSE if no error indicated
#         ret_arr["errno"]     = error number in case of error, otherwise 0
#
function mysql_recv_packet(socket) {

  local_var socket;
  local_var ret_arr, res, len;

  if (!socket) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#mysql_recv_packet");
    exit(0);
  }

  ret_arr["err"] = FALSE;
  ret_arr["errno"] = 0;

  if (!socket) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(),
                value: get_script_oid() + "#-#socket#-#mysql_recv_packet");
    exit(0);
  }

  res = recv(socket: socket, length: 4);
  if (!res || strlen(res) < 4)
    return;

  len = ord(res[0]) + (ord(res[1]) / 8) + (ord(res[2]) / 16);
  ret_arr["pkt_len"] = len;
  ret_arr["pkt_seqid"] = ord(res[3]);

  res = recv(socket: socket, length: len);
  if (!res || strlen(res) < len)
    return;

  if (hexstr(res[0]) == "ff") {
    ret_arr["err"] = TRUE;
    ret_arr["errno"] = ord(res[2]) << 8 | ord(res[1]);
  }

  ret_arr["data"] = res;

  return ret_arr;
}

# @brief Creates a 20-byte scrambled password for Secure Password Authentication
#        (see https://dev.mysql.com/doc/internals/en/secure-password-authentication.html)
#        scramble = SHA1(password) XOR SHA1("20-bytes random data from server" <concat> SHA1(SHA1(password)))
#
# @param password The password to scramble
# @param salt     The 20-byte random challenge received from server
#
# @return 20-byte scrambled password to authenticate with the server
#
function mysql_scramble_password(password, salt) {

  local_var password, salt;
  local_var scramble, stage1, stage2, stage3, i;

  scramble = "";
  stage1 = SHA1(password);
  stage2 = SHA1(stage1);
  stage3 = SHA1(string(salt, stage2));

  for (i = 0; i < strlen(stage3); i++)
    scramble += raw_string(ord(stage1[i])^ord(stage3[i]));

  return scramble;
}

# @brief Extracts the salt from the initial handshake response
#
# @param data The handshake response which contains the salt (usually from mysql_recv_server_handshake())
#
# @return the extracted salt
#         FALSE otherwise
#
function mysql_get_salt(data) {

  local_var data;
  local_var vers_length, i, salt;

  vers_length = 0;

  # version length is variable (null-terminated string)
  for (i = 1; i < strlen(data); i++) {
    if (ord(data[i]) == 0) {
      vers_length = i;
      break;
    }
  }

  if (vers_length == 0)
    return FALSE;

  if (strlen(data) < 43 + vers_length)
    return FALSE;

  # first 8-byte salt (this is from the old password authentication)
  salt = substr(data, vers_length + 5, vers_length + 12);

  # the remaining 12-bytes from the 20-byte challenge
  # Note: This additional bytes are just present if Protocol 4.1 is supported and authentication plugin
  # mysql_native_password is set
  if (strlen(data) > vers_length + 44)
    salt += substr(data, vers_length + 32, vers_length + 43);

  return salt;
}

# @brief Tries to login to the MySQL server with Protocol 4.1 (mysql_native_password) without SSL
#
# @param socket   The existing socket to the server
# @param user     Username
# @param password The password
# @param db       Database name to connect to (optional)
#
# @return TRUE if login was successful
#         FALSE otherwise
#
# TODO: - Make client capabilities adjustable
#       - Check server capabilities to adjust requests
#       - Support Protocol version < 4.1
#       - Support SSL
#
function mysql_login(socket, user, password, db) {

  local_var socket, user, password, db;
  local_var res, salt, scramble, data;

  if (!socket) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#socket#-#mysql_login");
    exit(0);
  }

  res = mysql_recv_server_handshake(socket: socket);

  if (!salt = mysql_get_salt(data: res))
    return FALSE;

  scramble = mysql_scramble_password(password: password, salt: salt);

  if (db)
    data = raw_string(0x0d, 0xa2) +                    # client capabilities
           raw_string(0x2a, 0x00) +                    # extended client capabilities
           raw_string(0xff, 0xff, 0xff, 0x00) +        # MAX packet
           raw_string(0x21) +                          # charset
           crap(data: raw_string(0x00), length: 23) +  # padding
           user + raw_string(0x00) +                   # username
           mkbyte(strlen(scramble)) +                  # length of scrambled password
           scramble +                                  # scrambled password
           db + raw_string(0x00) +                     # DB to connect to
           "mysql_native_password" + raw_string(0x00); # Client Auth plugin
  else
    data = raw_string(0x05, 0xa2) +                    # client capabilities
           raw_string(0x2a, 0x00) +                    # extended client capabilities
           raw_string(0xff, 0xff, 0xff, 0x00) +        # MAX packet
           raw_string(0x21) +                          # charset
           crap(data: raw_string(0x00), length: 23) +  # padding
           user + raw_string(0x00) +                   # username
           mkbyte(strlen(scramble)) +                  # length of scrambled password
           scramble +                                  # scrambled password
           "mysql_native_password" + raw_string(0x00); # Client Auth plugin

  mysql_send_packet(socket: socket, data: data);

  res = mysql_recv_packet(socket: socket);

  #display('Response\nLength:         ', res["pkt_len"],
  #        '\nSequenceID:     ', res["pkt_seqid"],
  #        '\nError:          ', res["err"],
  #        '\nErrorNum:       ', res["errno"],
  #        '\nPacket:\n', hexdump(ddata: res["data"]));
  if (res["err"])
    return FALSE;

  return TRUE;
}
