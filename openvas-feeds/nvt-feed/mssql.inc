# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# note: The mssql_make_login_pkt() and mssql_recv() functions got taken from the following VTs
# (and removed from them) which had different Copyright holders / years but the same GPL-2.0-only
# license:
# - pre2008/mssql_blank_password.nasl
#   - Copyright (C) 2001 HD Moore
#   - mssql_make_login_pkt() only
# - pre2008/mssql_brute_force.nasl
#   - Copyright (C) 2005 HD Moore
#   - mssql_make_login_pkt() and mssql_recv()

global_var mssql_pkt_hdr, mssql_pkt_pt2, mssql_pkt_pt3, mssql_pkt_lang;

mssql_pkt_hdr = raw_string(
  0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
);

mssql_pkt_pt2 = raw_string (
  0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x61, 0x30, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x20, 0x18, 0x81, 0xb8, 0x2c, 0x08, 0x03,
  0x01, 0x06, 0x0a, 0x09, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x73, 0x71, 0x75, 0x65, 0x6c, 0x64, 0x61,
  0x20, 0x31, 0x2e, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00
);

mssql_pkt_pt3 = raw_string (
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x4d, 0x53, 0x44,
  0x42, 0x4c, 0x49, 0x42, 0x00, 0x00, 0x00, 0x07, 0x06, 0x00, 0x00,
  0x00, 0x00, 0x0d, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00
);

mssql_pkt_lang = raw_string(
  0x02, 0x01, 0x00, 0x47, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x30, 0x30, 0x30, 0x00, 0x00,
  0x00, 0x03, 0x00, 0x00, 0x00
);

# @brief Receives a MSSQL packet from a given socket.
#
# @param socket The open TCP socket to read the data from.
#
# @return The received MSSQL packet as a raw string, NULL if a too short (< 4 bytes) packet was
#         received or FALSE if no socket has been given.
#
function mssql_recv(socket) {

  local_var socket;
  local_var head, len_hi, len_lo, len, body;

  if(!socket) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#socket#-#mssql_recv");
    return FALSE;
  }

  head = recv(socket:socket, length:4, min:4);
  if(strlen(head) < 4)
    return NULL;

  len_hi = 256 * ord(head[2]);
  len_lo = ord(head[3]);

  len = len_hi + len_lo;
  body = recv(socket:socket, length:len);
  return(string(head, body));
}

# @brief Creates a MSSQL TDS4/5 login packet based on the given credentials
#
# @param username The username to be used in the login packet
# @param password The password to be used in the login packet
#
# @info https://www.freetds.org/tds.html
#
# @return The created MSSQL TDS4/5 login packet
#
function mssql_make_login_pkt(username, password) {

  # nb: mssql_pkt_hdr, mssql_pkt_pt2 and mssql_pkt_pt3 are global vars
  local_var username, password;
  local_var ulen, plen, upad, ppad, ubuf, pbuf, nul, ublen, pblen, sql_packet;

  ulen = strlen(username);
  plen = strlen(password);

  upad = 30 - ulen;
  ppad = 30 - plen;

  ubuf = "";
  pbuf = "";

  nul = raw_string(0x00);

  if(ulen) {
    ublen = raw_string(ulen % 255);
  } else {
    ublen = raw_string(0x00);
  }

  if(plen) {
    pblen = raw_string(plen % 255);
  } else {
    pblen = raw_string(0x00);
  }

  ubuf = string(username, crap(data:nul, length:upad));
  pbuf = string(password, crap(data:nul, length:ppad));

  sql_packet = string(mssql_pkt_hdr, ubuf, ublen, pbuf, pblen, mssql_pkt_pt2, pblen, pbuf, mssql_pkt_pt3);

  # nb: Returning this as a string is NOT working!
  return sql_packet;
}

# @brief Translates the version into the major release name
#
# @param version The version to translate
#
# @return The release name associated with this version
#
# @info https://en.wikipedia.org/wiki/History_of_Microsoft_SQL_Server#Release_summary
#       https://sqlserverbuilds.blogspot.com/
#
function mssql_get_rel_name(version) {

  local_var version;

  if (version =~ "^1\.0") {
    return "1.0";
  } else if (version =~ "^1\.1") {
    return "1.1";
  } else if (version =~ "^4\.2") {
    return "4.2";
  } else if (version =~ "^6\.0") {
    return "6.0";
  } else if (version =~ "^6\.5") {
    if (version =~ "^6\.5\.201\.") {
      return "6.5";
    } else if (version =~ "^6\.5\.213") {
      return "6.5 SP1";
    } else if (version =~ "^6\.5\.240") {
      return "6.5 SP2";
    } else if (version =~ "^6\.5\.258") {
      return "6.5 SP3";
    } else if (version =~ "^6\.5\.281") {
      return "6.5 SP4";
    } else if (version =~ "^6\.5\.415") {
      return "6.5 SP5";
    } else if (version =~ "^6\.5\.416") {
      return "6.5 SP5a";
    } else {
      return "6.5";
    }
  } else if (version =~ "^7\.0") {
    if (version =~ "^7\.0\.623") {
      return "7.0";
    } else if (version =~ "^7\.0\.699") {
      return "7.0 SP1";
    } else if (version =~ "^7\.0\.842") {
      return "7.0 SP2";
    } else if (version =~ "^7\.0\.961") {
      return "7.0 SP3";
    } else if (version =~ "^7\.0\.1063") {
      return "7.0 SP4";
    } else {
      return "7.0";
    }
  } else if (version =~ "^8\.0") {
    if (version =~ "^8\.0\.194") {
      return "2000";
    } else if (version =~ "^8\.0\.384") {
      return "2000 SP1";
    } else if (version =~ "^8\.0\.53[24]") {
      return "2000 SP2";
    } else if (version =~ "^8\.0\.760") {
      return "2000 SP3";
    } else if (version =~ "^8\.0\.766") {
      return "2000 SP3a";
    } else if (version =~ "^8\.0\.2039") {
      return "2000 SP4";
    } else {
      return "2000";
    }
  } else if (version =~ "^9\.0") {
    if (version =~ "^9\.0\.1399") {
      return "2005";
    } else if (version =~ "^9\.0\.2047") {
      return "2005 SP1";
    } else if (version =~ "^9\.0\.3042") {
      return "2005 SP2";
    } else if (version =~ "^9\.0\.4035") {
      return "2005 SP3";
    } else if (version =~ "^9\.0\.5[0-9]{3}") {
      return "2005 SP4";
    } else {
      return "2005";
    }
  } else if (version =~ "^10\.0") {
    if (version =~ "^10\.0\.1600") {
      return "2008";
    } else if (version =~ "^10\.0\.2531") {
      return "2008 SP1";
    } else if (version =~ "^10\.0\.4[0-9]{3}") {
      return "2008 SP2";
    } else if (version =~ "^10\.0\.55[0-9]{2}") {
      return "2008 SP3";
    } else if (version =~ "^10\.0\.6[0-9]{3}") {
      return "2008 SP4";
    } else {
      return "2008";
    }
  } else if (version =~ "^10\.50") {
    if (version =~ "^10\.50\.1600") {
      return "2008 R2";
    } else if (version =~ "^10\.50\.25[0-9]{2}") {
      return "2008 R2 SP1";
    } else if (version =~ "^10\.50\.4[0-9]{3}") {
      return "2008 R2 SP2";
    } else if (version =~ "^10\.50\.6[0-9]{3}") {
      return "2008 R2 SP3";
    } else {
      return "2008 R2";
    }
  } else if (version =~ "^11\.0") {
    if (version =~ "^11\.0\.3[0-9]{3}") {
      return "2012 SP1";
    } else if (version =~ "^11\.0\.5[0-9]{3}") {
      return "2012 SP2";
    } else if (version =~ "^11\.0\.6[0-9]{3}") {
      return "2012 SP3";
    } else if (version =~ "^11\.0\.7[0-9]{3}") {
      return "2012 SP4";
    } else {
      return "2012";
    }
  } else if (version =~ "^12\.0") {
    if (version =~ "^12\.0\.4[0-9]{3}") {
      return "2014 SP1";
    } else if (version =~ "^12\.0\.5[0-9]{3}") {
      return "2014 SP2";
    } else if (version =~ "^12\.0\.6[0-9]{3}") {
      return "2014 SP3";
    } else {
      return "2014";
    }
  } else if (version =~ "^13\.0") {
    if (version =~ "^13\.0\.4[0-9]{3}") {
      return "2016 SP1";
    } else if (version =~ "^13\.0\.5[0-9]{3}") {
      return "2016 SP2";
    } else if (version =~ "^13\.0\.[67][0-9]{3}") {
      # nb: For 2016 SP3 (13.0.6xxx) and Azure connect feature pack for SQL Server 2016 Service Pack 3 (13.0.7xxx)
      return "2016 SP3";
    } else {
      return "2016";
    }
  # nb: Starting from SQL Server 2017 Service Packs will no longer be released
  } else if (version =~ "^14\.0") {
    return "2017";
  } else if (version =~ "^15\.0") {
    return "2019";
  } else if (version =~ "^16\.0") {
    return "2022";
  } else {
    return "unknown release name";
  }
}
