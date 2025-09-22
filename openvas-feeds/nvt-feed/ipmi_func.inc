# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# IPMI related functions

global_var IPMI_1_5_AUTHENTICATION_ALG_MD5, IPMI_1_5_AUTHENTICATION_ALG_PW;
global_var IPMI_1_5_AUTHENTICATION_TYPE_MD5, IPMI_1_5_AUTHENTICATION_TYPE_PW;
global_var IPMI_2_PAYLOAD_RMCPPLUSOPEN_REQ, IPMI_2_PAYLOAD_RMCPPLUSOPEN_REP;
global_var IPMI_2_PAYLOAD_RAKP1, IPMI_2_PAYLOAD_RAKP2;

IPMI_1_5_AUTHENTICATION_ALG_MD5 = "MD5";             # MD5 based
IPMI_1_5_AUTHENTICATION_TYPE_MD5 = raw_string(0x02);
IPMI_1_5_AUTHENTICATION_ALG_PW = "PW";               # Password based
IPMI_1_5_AUTHENTICATION_TYPE_PW = raw_string(0x04);

IPMI_2_PAYLOAD_RMCPPLUSOPEN_REQ = raw_string(0x10);  # RCMP+ Open Session Request, not encrypted, not authenticated
IPMI_2_PAYLOAD_RMCPPLUSOPEN_REP = raw_string(0x11);  # RCMP+ Open Session Response, not encrypted, not authenticated
IPMI_2_PAYLOAD_RAKP1            = raw_string(0x12);  # Payload Type: RAKP Message 1, not encrypted, not authenticated
IPMI_2_PAYLOAD_RAKP2            = raw_string(0x13);  # Payload Type: RAKP Message 2, not encrypted, not authenticated

# @brief Calculates the 2's complement checksum of a number of bytes
#
# 8-bit checksum algorithm: Initialize checksum to 0. For each byte,
# checksum = (checksum + byte) modulo 256.
# Then checksum = - checksum.
# @see http://www.staroceans.org/e-book/ipmi-spec-rev1_5.pdf (Section 13.4.3 Message Fields)
#
# @param blob The bytes on which the checksum should be calculated
#
# @return The calculated checksum or NULL in case of an error
#
function ipmi_v1_5_calc_checksum(blob) {
  local_var blob;
  local_var checksum, i;

  if (!blob) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#blob#-#ipmi_v1_5_calc_checksum");
    return NULL;
  }

  checksum = 0;
  for (i = 0; i < strlen(blob); i++)
    checksum = (checksum + ord(blob[i])) % 256;

  return 0x100 - checksum;
}

# @brief Calculates a hash depending on the algorithm
#
# @see http://www.staroceans.org/e-book/ipmi-spec-rev1_5.pdf (Section 18.15.1 AuthCode Algorithms)
#
# @param alg The hash algorithm (MD5 or none if password only)
# @param password The password of the user
# @param session_id The session ID received from the server
# @param data The data which needs to be sent in further requests
# @param seq_nr The sequence number to use
#
# @return The calculated hash (MD5) of the data or the password or NULL in case of an error
#
function ipmi_v1_5_create_hash(alg, password, session_id, data, seq_nr) {
  local_var alg, password, session_id, data, seq_nr;

  if (!alg) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#alg#-#ipmi_v1_5_create_hash");
    return NULL;
  }

  if (alg != IPMI_1_5_AUTHENTICATION_ALG_MD5 && alg != IPMI_1_5_AUTHENTICATION_ALG_PW) {
    set_kb_item(name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#ipmi_v1_5_create_hash(): Wrong algorithm");
    return NULL;
  }

  if (!password) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#password#-#ipmi_v1_5_create_hash");
    return NULL;
  }

  if (!session_id) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#session_id#-#ipmi_v1_5_create_hash");
    return NULL;
  }

  if (!data) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#ipmi_v1_5_create_hash");
    return NULL;
  }

  if (!seq_nr) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#seq_nr#-#ipmi_v1_5_create_hash");
    return NULL;
  }

  if (alg == IPMI_1_5_AUTHENTICATION_ALG_MD5)
    return MD5(password + session_id + data + seq_nr + password);
  else
    return password;
}

# @brief Creates a IPMI v1.5 Get Channel Authentication Capabilities
#
# @see http://www.staroceans.org/e-book/ipmi-spec-rev1_5.pdf (Section 18.12 Get Channel Authentication Capabilities Command)
#
# @param debug (optional) If TRUE print out debug messages
#
# @return A raw string with the created request
#
function ipmi_v1_5_create_get_channel_auth_cap(debug) {
  local_var debug;
  local_var header, message, packet;

  header = raw_string(0x06, 0x00, 0xff, 0x07,           # Remote Management Control Protocol
                      0x00,                             # Authentication Type: NONE
                      0x00, 0x00, 0x00, 0x00,           # Session Sequence Number
                      0x00, 0x00, 0x00, 0x00);          # Session ID

  message = raw_string(0x20,                            # Responder Address
                       0x18,                            # netFn/rsLUN
                       ipmi_v1_5_calc_checksum(blob: raw_string(0x20, 0x18)),  # Checksum
                       0x81,                            # Requester Address
                       0x04,                            # reqSeq, reqLUN
                       0x38,                            # Get Channel Auth Capabilities (command)
                       0x0e,                            # Channel Number (this channel)
                       0x04,                            # Request Administrator level
                       ipmi_v1_5_calc_checksum(blob: raw_string(0x81, 0x04, 0x38, 0x0e, 0x04))); #Checksum

  packet = header + mkbyte(strlen(message)) + message;

  if (debug)
    display('IPMI v1.5 Get Channel Authentication Capabilities Request:\n' + hexdump(ddata: packet));

  return packet;
}

# @brief Creates a IPMI v1.5 Get Session Challenge
#
# @see http://www.staroceans.org/e-book/ipmi-spec-rev1_5.pdf (Section 18.14 Get Session Challenge Command)
#
# @param auth_type Authentication Type
# @param username Username to get the challenge for (must be padded)
# @param debug (optional) If TRUE print out debug messages
#
# @return A raw string with the created request or NULL in case of an error
#
function ipmi_v1_5_create_get_session_challenge(auth_type, username, debug) {
  local_var auth_type, username, debug;
  local_var header, message, packet;

  if (!auth_type) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#auth_type#-#ipmi_v1_5_create_get_session_challenge");
    return NULL;
  }

  if (auth_type != IPMI_1_5_AUTHENTICATION_TYPE_MD5 && auth_type != IPMI_1_5_AUTHENTICATION_TYPE_PW) {
    set_kb_item(name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#ipmi_v1_5_create_get_session_challenge(): Wrong auth_type");
      return NULL;
  }

  if (!username || strlen(username) < 16) {
    set_kb_item(name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#ipmi_v1_5_create_get_session_challenge(): No username provided or username is not padded");
      return NULL;
  }

  header = raw_string(0x06, 0x00, 0xff, 0x07,           # Remote Management Control Protocol
                      0x00,                             # Authentication Type: NONE
                      0x00, 0x00, 0x00, 0x00,           # Session Sequence Number
                      0x00, 0x00, 0x00, 0x00);          # Session ID

  message = raw_string(0x20,                            # Responder Address
                       0x18,                            # netFn/rsLUN
                       ipmi_v1_5_calc_checksum(blob: raw_string(0x20, 0x18)),  # Checksum
                       0x81,                            # Requester Address
                       0x08,                            # reqSeq, reqLUN
                       0x39,                            # Get Session Challenge (command)
                       auth_type,                       # Auth Type for Challenge
                       username,                        # Username (padded)
                       ipmi_v1_5_calc_checksum(blob: raw_string(0x81, 0x08, 0x39, auth_type, username))); #Checksum

  packet = header + mkbyte(strlen(message)) + message;

  if (debug)
    display('IPMI v1.5 Get Session Challenge:\n' + hexdump(ddata: packet));

  return packet;
}

# @brief Creates a IPMI v1.5 Activate Session request
#
# @see http://www.staroceans.org/e-book/ipmi-spec-rev1_5.pdf (Section 18.15 Activate Session Command)
#
# @param auth_type Authentication Type
# @param auth_alg Authentication Algorithm
# @param challenge The challenge received from the server
# @param password (optional) The password for the user (default empty)
# @param session_id The session ID received from the server
# @param sequence_num (optional) A session sequence number (default 0x00, 0x00, 0x00, 0x00)
# @param debug (optional) If TRUE print out debug messages
#
# @return A raw string with the created request or NULL in case of an error
#
function ipmi_v1_5_create_activate_session_request(auth_type, auth_alg, challenge, password, session_id, sequence_num, debug) {
  local_var auth_type, auth_alg, challenge, password, session_id, sequence_num, debug;
  local_var paddedPassword, data, checksum, authCode, header, message, packet;

  if (!auth_type) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#auth_type#-#ipmi_v1_5_create_activate_session_request");
    return NULL;
  }

  if (auth_type != IPMI_1_5_AUTHENTICATION_TYPE_MD5 && auth_type != IPMI_1_5_AUTHENTICATION_TYPE_PW) {
    set_kb_item(name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#ipmi_v1_5_create_activate_session_request(): Wrong auth_type");
      return NULL;
  }

  if (!auth_alg) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#auth_alg#-#ipmi_v1_5_create_activate_session_request");
    return NULL;
  }

  if (auth_alg != IPMI_1_5_AUTHENTICATION_ALG_MD5 && auth_alg != IPMI_1_5_AUTHENTICATION_ALG_PW) {
    set_kb_item(name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#ipmi_v1_5_create_activate_session_request: Wrong algorithm");
    return NULL;
  }

  if (!challenge) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#challenge#-#ipmi_v1_5_create_activate_session_request");
    return NULL;
  }

  if (!password)
    password = "";

  if (!session_id) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#session_id#-#ipmi_v1_5_create_activate_session_request");
    return NULL;
  }

  if (!sequence_num)
    sequence_num = raw_string(0x00, 0x00, 0x00, 0x00);

  paddedPassword = password;
  while (strlen(paddedPassword) < 16)
    paddedPassword = paddedPassword + raw_string(0x00);

  data = raw_string(0x20, 0x18, 0xc8, 0x81, 0x0c, 0x3a, auth_type, 0x04, challenge,
                    0xaa, 0x9b, 0x59, 0x3a);
  checksum = ipmi_v1_5_calc_checksum(blob: data);
  data = raw_string(data, checksum);

  if (!authCode = ipmi_v1_5_create_hash(alg: auth_alg, password: paddedPassword, session_id: session_id,
                                        data: data, seq_nr: sequence_num))
    return NULL;

  header = raw_string(0x06, 0x00, 0xff, 0x07,           # Remote Management Control Protocol
                      auth_type,                        # Authentication Type
                      sequence_num,                     # Session Sequence Number
                      session_id,                       # Session ID
                      authCode);                        # Authentication Code

  message = raw_string(0x20,                            # Responder Address
                       0x18,                            # netFn/rsLUN
                       ipmi_v1_5_calc_checksum(blob: raw_string(0x20, 0x18)),  # Checksum
                       0x81,                            # Requester Address
                       0x0c,                            # reqSeq/reqLUN
                       0x3a,                            # Activate Session (command)
                       auth_type,                       # Authentication Type
                       0x04,                            # Max Priv Level (Administrator level)
                       challenge,                       # Challenge
                       0xaa, 0x9b, 0x59, 0x3a,          # initial outbound seq number
                       checksum);                       # Checksum

  packet = header + mkbyte(strlen(message)) + message;

  if (debug)
    display('IPMI v1.5 Activate Session Request:\n' + hexdump(ddata: packet));

  return packet;
}

# @brief Creates a IPMI v1.5 close session request
#
# @see http://www.staroceans.org/e-book/ipmi-spec-rev1_5.pdf (Section 18.17 Close Session Command)
#
# @param auth_type Authentication Type
# @param auth_alg Authentication Algorithm
# @param password (optional) The password for the user (default empty)
# @param session_id The session ID received from the server
# @param sequence_num (optional) A session sequence number (default 0x01, 0x00, 0x00, 0x00)
# @param debug (optional) If TRUE print out debug messages
#
# @return A raw string with the created request or NULL in case of an error
#
function ipmi_v1_5_create_close_session_request(auth_type, auth_alg, password, session_id, sequence_num, debug) {
  local_var auth_type, auth_alg, password, session_id, sequence_num, debug;
  local_var paddedPassword, data, checksum, authCode, header, message, packet;

  if (!auth_type) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#auth_type#-#ipmi_v1_5_create_close_session_request");
    return NULL;
  }

  if (auth_type != IPMI_1_5_AUTHENTICATION_TYPE_MD5 && auth_type != IPMI_1_5_AUTHENTICATION_TYPE_PW) {
    set_kb_item(name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#ipmi_v1_5_create_close_session_request(): Wrong auth_type");
    return NULL;
  }

  if (!auth_alg) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#auth_alg#-#ipmi_v1_5_create_close_session_request");
    return NULL;
  }

  if (auth_alg != IPMI_1_5_AUTHENTICATION_ALG_MD5 && auth_alg != IPMI_1_5_AUTHENTICATION_ALG_PW) {
    set_kb_item(name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#ipmi_v1_5_create_close_session_request: Wrong algorithm");
    return NULL;
  }

  if (!password)
    password = "";

  if (!session_id) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#session_id#-#ipmi_v1_5_create_close_session_request");
    return NULL;
  }

  if (!sequence_num)
    sequence_num = raw_string(0x01, 0x00, 0x00, 0x00);

  paddedPassword = password;
  while (strlen(paddedPassword) < 16)
    paddedPassword = paddedPassword + raw_string(0x00);

  data = raw_string(0x20, 0x18, 0xc8, 0x81, 0x0c, 0x3c, session_id);
  checksum = ipmi_v1_5_calc_checksum(blob: data);
  data = raw_string(data, checksum);

  if (!authCode = ipmi_v1_5_create_hash(alg: auth_alg, password: paddedPassword, session_id: session_id,
                                        data: data, seq_nr: sequence_num))
    return NULL;

  header = raw_string(0x06, 0x00, 0xff, 0x07,           # Remote Management Control Protocol
                      auth_type,                        # Authentication Type
                      sequence_num,                     # Session Sequence Number
                      session_id,                       # Session ID
                      authCode);                        # Authentication Code

  message = raw_string(0x20,                            # Responder Address
                       0x18,                            # netFn/rsLUN
                       ipmi_v1_5_calc_checksum(blob: raw_string(0x20, 0x18)),  # Checksum
                       0x81,                            # Requester Address
                       0x0c,                            # reqSeq/reqLUN
                       0x3c,                            # Close Session (command)
                       session_id,                      # Session ID
                       checksum);                       # Checksum

  packet = header + mkbyte(strlen(message)) + message;

  if (debug)
    display('IPMI v1.5 Close Session Request:\n' + hexdump(ddata: packet));

  return packet;
}

# @brief Creates an IPMI v2.0 Open Session Request
#
# @param session_id Session ID to use
# @param debug (optional) If TRUE print out debug messages
#
# @return A raw string with the created request or NULL in case of an error.
#
function ipmi_v2_create_open_session_request(console_session_id, debug) {
  local_var console_session_id, debug;
  local_var header, data, packet;

  if (!console_session_id) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#console_session_id#-#ipmi_v2_create_open_session_request");
    return NULL;
  }

  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

  header = raw_string(0x06, 0x00, 0xff, 0x07,           # Remote Management Control Protocol
                      0x06,                             # Authentication Type: RMCP+
                      IPMI_2_PAYLOAD_RMCPPLUSOPEN_REQ,  # Payload Type
                      0x00, 0x00, 0x00, 0x00,           # Session ID
                      0x00, 0x00, 0x00, 0x00);          # Session Sequence Number

  data = raw_string(0x00, 0x00,                         # Maximum Access
                    0x00, 0x00,                         # Reserved
                    mkdword(console_session_id),        # Console Session ID
                    0x00, 0x00, 0x00, 0x08,
                    0x01, 0x00, 0x00, 0x00,
                    0x01, 0x00, 0x00, 0x08,
                    0x01, 0x00, 0x00, 0x00,             # HMAC-SHA1
                    0x02, 0x00, 0x00, 0x08,
                    0x01, 0x00, 0x00, 0x00);            # AES Encryption

  packet = header + mkword(strlen(data)) + data;

  if (debug)
    display('IPMI v2.0 Open Session Request:\n' + hexdump(ddata: packet));

  return packet;
}

# @brief Parses the response to an IPMI v2 Open Session Request
#
# @param data Open Session Response to parse
# @debug debug (optional) If TRUE print out debug messages
#
# @return Returns the supplied BMC Session ID or NULL in case of an error while parsing
#
function ipmi_v2_parse_open_session_reply(data, debug) {
  local_var data, debug;
  local_var offset, len, message;
  local_var bmc_session_id;

  if (!data) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#ipmi_v2_parse_open_session_reply");
    return NULL;
  }

  if (strlen(data) < 52 || hexstr(data) !~ "^0600ff07")
    return NULL;

  offset = 4; # Skip Remote Management Control Protocol part

  if (data[offset + 1] != IPMI_2_PAYLOAD_RMCPPLUSOPEN_REP)
    return NULL;

  len = getword(blob: data, pos: offset + 10);
  message = substr(data, offset + 12);

  if (debug)
    display('IPMI v2.0 Open Session Response Message:\n' + hexdump(ddata: message));

  # nb: Check for RMCP Error code
  if (hexstr(message[1]) != "00")
    return NULL;

  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

  bmc_session_id = getdword(blob: message, pos: 8);

  return bmc_session_id;
}

# @brief Creates a IPMI v2.0 RAKP Message 1
#
# @param bmc_session_id BMC Session ID probided by the server
# @param username Username to create the message for
# @param console_id (optional, otherwise a random one will be created) Console ID (16 bytes)
# @param debug (optional) If TRUE print out debug messages
#
# @ return The created RAKP Message 1 packet or NULL in case of an error
#
function ipmi_v2_create_rakp_message_1(bmc_session_id, console_id, username, debug) {
  local_var bmc_session_id, username, console_id, debug;
  local_var header, data, packet;

  if (!bmc_session_id) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#bmc_session_id#-#ipmi_v2_create_rakp_message_1");
    return NULL;
  }

  if (!username)
    username = "";

  header = raw_string(0x06, 0x00, 0xff, 0x07,           # Remote Management Control Protocol
                      0x06,                             # Authentication Type: RMCP+
                      IPMI_2_PAYLOAD_RAKP1,             # Payload Type
                      0x00, 0x00, 0x00, 0x00,           # Session ID
                      0x00, 0x00, 0x00, 0x00);          # Session Sequence Number

  if (!console_id) {
    data = raw_string(0x00, 0x00, 0x00, 0x00,
                      mkdword(bmc_session_id),            # BMC Session ID
                      mkdword(rand()),                    # Console ID
                      mkdword(rand()),
                      mkdword(rand()),
                      mkdword(rand()),
                      0x14, 0x00, 0x00,
                      mkbyte(strlen(username)),           # Username length
                      username);                          # Username
  } else {
    if (strlen(console_id) != 16) {
      set_kb_item(name: "vt_debug_misc/" + get_script_oid(), value: get_script_oid() + "#-#ipmi_v2_create_rakp_message_1(): console_id has wrong length");
      return NULL;
    }

    data = raw_string(0x00, 0x00, 0x00, 0x00,
                      mkdword(bmc_session_id),            # BMC Session ID
                      console_id,                         # Console ID
                      0x14, 0x00, 0x00,
                      mkbyte(strlen(username)),           # Username length
                      username);
  }

  packet = header + mkword(strlen(data)) + data;

  if (debug)
    display('IPMI v2.0 Create RAKP Message 1 Request:\n' + hexdump(ddata: packet));

  return packet;
}

# @brief Parses the response to an IPMI v2 RAKP Request
#
# @param data RAKP Response to parse
# @debug debug (optional) If TRUE print out debug messages
#
# @return An array containing the extracted information or NULL in case of an error
#
#         ret_array["hash"]        = SHA1 Hash sent by the server
#         ret_array["bmc_guid"]    = BMC GUID
#         ret_array["rand_bmc_id"] = BMC ID sent by the server
#
function ipmi_v2_parse_rakp_message_reply(data, debug) {
  local_var data, debug;
  local_var offset, len, message, hash, bmc_guid, rand_bmc_id;
  local_var res;

  res = make_array();

  if (!data) {
    set_kb_item(name: "vt_debug_empty/" + get_script_oid(), value: get_script_oid() + "#-#data#-#ipmi_v2_parse_rakp_message_reply");
    return NULL;
  }

  # nb: Response seems to not included a valid hash or is not an IPMI response
  if (strlen(data) < 76 || hexstr(data) !~ "^0600ff07")
    return NULL;

  offset = 4; # Skip Remote Management Control Protocol part

  if (data[offset + 1] != IPMI_2_PAYLOAD_RAKP2)
    return NULL;

  len = getword(blob: data, pos: offset + 10);
  message = substr(data, offset + 12);

  if (debug)
    display('IPMI v2.0 RAKP2 Response Message:\n' + hexdump(ddata: message));

  # nb: Check for RMCP Error code
  if (hexstr(message[1]) != "00")
    return NULL;

  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

  hash = substr(message, 40);

  if (hexstr(hash) == "0000000000000000000000000000000000000000")
    return NULL;

  bmc_guid = substr(message, 24, 39);
  rand_bmc_id = substr(message, 8, 23);

  res["hash"] = hash;
  res["bmc_guid"] = bmc_guid;
  res["rand_bmc_id"] = rand_bmc_id;

  return res;
}
