# SPDX-FileCopyrightText: 2026 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# @brief Creates a Modbus "Read Device Identification" request
#
# @param unit_id The (optional) Unit ID to query. If not given a Unit ID "0" is used/assumed.
#
# @note https://www.modbus.org/file/secure/modbusprotocolspecification.pdf (Page 43)
#
# @return The created request as a raw string
#
function modbus_create_dev_info_req( unit_id ) {

  local_var unit_id;
  local_var req;

  if( isnull( unit_id ) )
    unit_id = 0;

  req = raw_string( 0x00, 0x00, # Transport ID
                    0x00, 0x00, # Protocol ID
                    0x00, 0x05, # Length
                    unit_id,    # Unit ID
                    0x2B,       # Function Code (Read Device Identification)
                    0x0E,       # MEI Type: (Read Device Identification)
                    0x01,       # Object ID (0x01: Basic, 0x02: Regular, 0x03: Extended)
                                # nb: Some devices do not response properly for regular and extended requests
                    0x00 );     # Vendor ID

  return req;
}
