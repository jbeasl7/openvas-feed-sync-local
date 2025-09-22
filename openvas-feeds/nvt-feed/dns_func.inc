# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Make various queries to the CHAOS TXT record and save the reply string in the KB for further analysis
#
# @param soc   Socket to run the query at
# @param proto Protocol to use ("tcp" or "udp")
# @param port  Port the socket is bound to
#
# @return The reply from the server as a string if there was no error, otherwise NULL.
#
function dnsVersionReq( soc, proto, port ) {

  local_var soc, proto, port;
  local_var raw_data_init, queries, query_list, _query, _query_str, len, raw_data, offset, result, base, size, slen, whole_data, i;

  if( ! soc ) {
    set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#soc#-#dnsVersionReq" );
    return NULL;
  }

  if( ! proto ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#proto#-#dnsVersionReq" );

  if( ! port ) set_kb_item( name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#dnsVersionReq" );

  raw_data_init = raw_string( 0x00, 0x0A, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07 );

  queries = make_list( "version",
                       "version.pdns",
                       "version.bind",
                       "version.server",
                       "erre-con-erre-cigarro.maradns.org",
                       "version.maradns", # Both found in https://maradns.samiam.org/tutorial/update.html
                       "version.mydns" ); # Found in https://github.com/dwighthubbard/mydns-dhubbard/blob/c8e4c1bb9834408b04ac8142628becef345496f5/src/mydns/status.c#L75

  query_list = make_list();

  # Try both lowercase and uppercase
  foreach _query( queries )
    query_list = make_list( query_list, _query, toupper( _query ) );

  foreach _query_str( query_list ) {

    if( proto == "tcp" ) {
      len = strlen( _query_str ) + 18;
      raw_data = raw_string( 0x00, len ) + raw_data_init;
      offset = 2;
    } else {
      offset = 0;
      raw_data = raw_data_init;
    }

    _query_str = str_replace( string:_query_str, find:".", replace:raw_string( 0x04 ) );
    raw_data = raw_data + _query_str;
    raw_data = raw_data + raw_string( 0x00, 0x00, 0x10, 0x00, 0x03 );

    send( socket:soc, data:raw_data );
    result = recv( socket:soc, length:1000 );

    if( result ) {
      if( ( ( result[0 + offset] == raw_string( 0x00 ) ) || ( result[0 + offset] == raw_string( 0xA5 ) ) ) &&
          ( ( result[1 + offset] == raw_string( 0x0A ) ) || ( result[1 + offset] == raw_string( 0x12 ) ) ) ) {

        if( ( ( result[2 + offset] == raw_string( 0x81 ) ) || ( result[2 + offset] == raw_string( 0x84 ) ) ||
            ( result[2 + offset] == raw_string( 0x85 ) ) ) &&
            ( ( result[3 + offset] == raw_string( 0x80 ) ) || ( result[3 + offset] == raw_string( 0x00 ) ) ) ) {

          if( ( result[4 + offset] == raw_string( 0x00 ) ) && ( result[5 + offset] == raw_string( 0x01 ) ) ) {

            if( ( result[6 + offset] == raw_string( 0x00 ) ) && ( result[7 + offset] == raw_string( 0x01 ) ) ) {

              if( result[18 + strlen( _query_str ) + offset] >= 0xc0 ) {
                base = 28 + strlen( _query_str );
              } else {
                base = 40 + strlen( _query_str );
              }

              size = ord( result[base + 1 + offset] );
              slen = base + 3 + offset - 1;
              if( slen > strlen( result ) )
                return;

              if( size > 0 ) {
                whole_data = "";
                for( i = 0; i < size - 1; i++ )
                  whole_data = whole_data + result[base + 3 + i + offset];

                set_kb_item( name:"DNS/" + proto + "/version_request", value:port );
                set_kb_item( name:"DNS/" + proto + "/version_request/" + port, value:whole_data );
                return whole_data;
              }
            }
          }
        }
      }
    }
  }
}

# @brief Extracts the full domain name (QNAME), handling also cases where links are present
#
# @param r the mDNS message (normally a reply)
# @param offset The offset in the mDNS message where the QNAME starts
#
# @return The full QNAME, resolving links and replacing them with the corresponding labels
#
function extractDomainName( r, offset ) {

  local_var r, offset, ptr_name, length, p_len, addr;

  length = strlen( r );
  ptr_name = "";

  while ( offset < length && ord( r[offset] ) > 0 ) {
    # nb: this happens only if this is a pointer
    if ( ( ord( r[offset] ) & 0xC0 ) == 0xC0 )
    {
      addr = ( ord( r[offset] ) & 0x03 ) * 256 + ord( r[offset + 1] );
      if ( addr < length ) {
        offset = addr;
      } else
        return NULL; # nb: something went wrong here
    } else {
      p_len = ord( r[offset] );
      ptr_name += r[offset];
      ptr_name += substr( r, offset + 1, offset + p_len );
      offset += p_len + 1;
    }
  }
  if ( offset < length && ord( r[offset] ) == 0 ) {
     ptr_name += r[offset];
  } else
    return NULL; # nb: something went wrong here

  return ptr_name;
}

# @brief Steps over a QNAME, handling links
#
# @param r the mDNS message (normally a reply)
# @param offset The offset in the mDNS message where the QNAME starts
#
# @return The offset in the message after the QNAME
#
function skipDomainName( r, offset ) {

  local_var r, offset, new_offset, p_len, was_link, length;

  was_link = FALSE;
  new_offset = offset;
  length = strlen( r );

  while ( new_offset < length && ord( r[new_offset] ) > 0 ) {
    # nb: this happens only if this is a pointer
    if ( ( ord( r[new_offset]) & 0xC0 ) == 0xC0 )
    {
      # nb: Since we do not care to retrieve the PTR, we know that in this case
      # there will ne only 2 more bytes (the link)
      new_offset += 2;
      was_link = TRUE;
      break;
    } else {
      p_len = ord( r[new_offset] );
      new_offset += 1 + p_len;
    }
  }
  if ( ! was_link )
    new_offset += 1; # nb: if there was no link, the Name is 0-terminated

  return new_offset;
}

# @brief Converts a QNAME to a domain name string, where labels are sepparated by a point.
#
# @param domainName the binary QNAME
#
# @return The string representation of the QNAME
#
function domainNameString( domainName ) {

  local_var domainName, offset, str, len, total_len;

  offset = 0;
  str = "";

  total_len = strlen( domainName );
  while ( offset < total_len )
  {
    len = ord( domainName[offset] );
    offset++;
    str += substr( domainName, offset, offset + len - 1 );
    offset += len;
    if ( offset < total_len && ord( domainName[offset] ) > 0 )
      str += ".";
  }
  return str;
}

# @brief Converts the numeric value of a DNS answer type to its string name.
#
# @param domainName the binary QNAME
#
# @return The string representation of the QNAME
#
# @note see https://en.wikipedia.org/wiki/List_of_DNS_record_types
#
function getDNSTypeName( type ) {

  local_var type;

  if ( type == 1 )
    return "A";
  if ( type == 12 )
    return "PTR";
  if ( type == 16 )
    return "TXT";
  if ( type == 28 )
    return "AAA";
  if ( type == 33 )
    return "SRV";
}

# @brief Parses the response to a PTR query message and returns a list with the results
#
# @param r the mDNS query response message
#
# @return An array of parsed DNS records, indexed by the record types
#
function parseDNSPTRResponse( r, query ) {

  local_var r, query, offset, nr_queries, answers, nr_answers, data_offset, mdns_port, mdns_name;
  local_var newQuery, i, type, cls, data_length, data, name_length, ip_adr, is_empty, type_name, elem;

  answers = make_array();
  offset = 2;

  if ( ! ( ord( r[2] ) & 0x80 ) )
    return NULL;

  offset += 2;
  nr_queries = getword( blob:r, pos:offset );

  offset += 2;
  nr_answers = getword( blob:r, pos:offset );

  offset += 4;

  nr_add_answers = getword( blob:r, pos:offset );

  offset += 2;

  newQuery = substr( r, 12, 12 + strlen( query ) - 1 );

  if ( newQuery != query)
    return NULL;

  offset += strlen( query ) + 4; # Length of query + type + class

  for ( i = 0; i < nr_answers + nr_add_answers; i++ ) {
    # nb: first part is always query QNAME, we need to skip it
    offset = skipDomainName( r:r, offset:offset );

    type = getword( blob:r, pos:offset );
    offset += 2; # type
    cls = getword( blob:r, pos:offset );
    offset += 2; # class
    offset += 4; # TTL
    data_length = getword( blob:r, pos:offset );
    offset += 2; # length of data
    data = substr( r, offset, offset + data_length - 1 );

    # nb: PTR Answers might contain links inside domain name, so we need to resolve them
    if ( type == 12 ) { # PTR
      data = extractDomainName( r:r, offset:offset );
    } else if ( type == 33 ) { # SRV
      # nb: priority and weight are not useful for now, thus are skipped
      data_offset = 4; # priority & weight
      mdns_port = getword( blob:data, pos:data_offset );
      data_offset += 2; # port
      name_length = ord( data[data_offset] );
      data_offset += 1; # length of name
      mdns_name = substr( data, data_offset, data_offset + name_length - 1 );
      elem = make_array( "port", mdns_port,
                         "name", mdns_name );
    } else if ( type == 1 ) { # A
      if ( strlen( data ) != 4 )
        continue; # nb: data should be 4 bytes
      ip_adr = "";
      for ( j = 0; j < 4; j++ ) {
        ip_adr += ord( data[j] );
        if ( j < 3 )
          ip_adr += ".";
      }
      data = ip_adr;

    } else if ( type == 28 ) { # AAA
      if ( strlen( data ) != 16 )
        continue; # nb: data should be 16 bytes
      ip_adr = "";
      is_empty = 0;
      for ( j = 0; j < 8; j++ ) {
        val = getword( blob:data, pos:j * 2 );
        # nb: logic to skip the empty values
        if ( val == 0 )
          is_empty++;
        else {
          is_empty = 0;
          ip_adr += hex( val );
        }
        if ( j < 7 && is_empty <= 1 )
          ip_adr += ":";
      }
      data = ip_adr;
    }

    offset += data_length;
    type_name = getDNSTypeName( type:type );
    # if type was SRV, elem is already set to an array
    if ( type != 33 ) { # 33 == SRV
      elem = data;
      # if there are multiple DNS records of same type, we add them to a list
      if ( ! isnull( elem ) && strlen( elem ) > 0 ) {
        if ( ! isnull( answers[type_name] ) )
          answers[type_name] = make_list( answers[type_name], elem );
        else
          answers[type_name] = make_list( elem );
      }
    } else # SRV case
      answers[type_name] = elem;
  }
  return answers;
}
