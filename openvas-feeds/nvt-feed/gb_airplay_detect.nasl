# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.154932");
  script_version("2025-07-25T15:43:57+0000");
  script_tag(name:"last_modification", value:"2025-07-25 15:43:57 +0000 (Fri, 25 Jul 2025)");
  script_tag(name:"creation_date", value:"2025-07-21 08:32:56 +0000 (Mon, 21 Jul 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("AirPlay Service Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 5000);

  script_tag(name:"summary", value:"TCP based detection of services supporting the AirPlay
  protocol.");

  script_xref(name:"URL", value:"https://www.apple.com/airplay/");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 5000);

url = "/info";

res = http_get_cache(port: port, item: url);

if (res !~ "^HTTP/1\.[01] 200" || ("AirPlay" >!< res && "application/x-apple-binary-plist" >!< res) ||
    "bplist00" >!< res)
  exit(0);

set_kb_item(name: "apple/airplay/detected", value: TRUE);
service_register(port: port, proto: "airplay");

if (pos = stridx(res, "bplist00")) {
  # nb: Extract the whole plist
  plist = substr(res, pos);

  # nb: Extract the footer
  footer = substr(plist, strlen(plist) - 32);

  # nb: Extract the size of the items in the offset table
  item_size = ord(footer[6]);
  # nb: Extract the number of objects in the offset table
  num_objects = getdword(blob: footer, pos: 12);

  # nb: Extract the starting index of the offset table
  offset_table_start = getdword(blob: footer, pos: strlen(footer) - 4);
  # nb: Extract the offset table
  offset_table = substr(plist, offset_table_start, strlen(plist) - 33);

  if (item_size == 2) {
    obj_pos = getword(blob: offset_table, pos: 0);
  } else {
    obj_pos = ord(offset_table[0]);
  }

  value_starter = plist[obj_pos];

  # nb: In our case this always needs to be a dictionary
  if (hexstr(value_starter) =~ "^d") {
    # nb: Handling of Dictionary
    if (hexstr(value_starter) == "df") {
      # Read the next two bytes to get the length
      # Currently we just ignore the first one as there shouldn't be anything bigger than 0xFF in our cases
      dict_size = ord(plist[obj_pos + 2]);

      off = obj_pos + 3;
      index = 0;
      keys = make_list();

      # Going through the dictionary to get the keys
      for (i = 0; i < dict_size; i++) {
        index = i + off;
        pos = ord(plist[index]) * item_size;

        if (item_size == 2)
          obj_offset = getword(blob: offset_table, pos: pos);
        else if (item_size == 1)
          obj_offset = ord(offset_table[pos]);

        object_starter = plist[obj_offset];

        # Handle Strings
        if (hexstr(object_starter) =~ "^5") {
          if (hexstr(object_starter) == "5f") {
            # Currently we just ignore the first one as there shouldn't be anything bigger than 0xFF
            # in our cases
            obj_size = ord(plist[obj_offset + 2]);
            object = substr(plist, obj_offset + 3, obj_offset + 2 + obj_size);
          } else {
            obj_size = ord(object_starter) - 80;
            object = substr(plist, obj_offset + 1, obj_offset + obj_size);
          }
          keys[i] = object;
        }
      }

      off = index + 1;
      values = make_list();

       # Going through the dictionary to get the keys
      for (i = 0; i <= dict_size; i++) {
        index = i + off;
        pos = ord(plist[index]) * item_size;

        if (item_size == 2)
          obj_offset = getword(blob: offset_table, pos: pos);
        else if (item_size == 1)
          obj_offset = ord(offset_table[pos]);

        object_starter = plist[obj_offset];

        # Handle Strings
        if (hexstr(object_starter) =~ "^5") {
          if (hexstr(object_starter) == "5f") {
            # Currently we just ignore the first one as there shouldn't be anything bigger than 0xFF
            # in our cases
            obj_size = ord(plist[obj_offset + 2]);
            object = substr(plist, obj_offset + 3, obj_offset + 2 + obj_size);
          } else {
            obj_size = ord(object_starter) - 80;
            object = substr(plist, obj_offset + 1, obj_offset + obj_size);
          }
          values[i] = object;
        } else {
          # nb: Non-strings are not interesting for us
          values[i] = "";
        }
      }
    } else {
      # nb: The size of the dictionary is the second nibble
      dict_size = ord(value_starter) % 0xd0;

      off = obj_pos + 1;
      index = 0;
      keys = make_list();

      # Going through the dictionary to get the keys
      for (i = 0; i < dict_size; i++) {
        index = i + off;
        pos = ord(plist[index]) * item_size;

        if (item_size == 2)
          obj_offset = getword(blob: offset_table, pos: pos);
        else if (item_size == 1)
          obj_offset = ord(offset_table[pos]);

        object_starter = plist[obj_offset];

        # Handle Strings
        if (hexstr(object_starter) =~ "^5") {
          if (hexstr(object_starter) == "5f") {
            # Currently we just ignore the first one as there shouldn't be anything bigger than 0xFF
            # in our cases
            obj_size = ord(plist[obj_offset + 2]);
            object = substr(plist, obj_offset + 3, obj_offset + 2 + obj_size);
          } else {
            obj_size = ord(object_starter) - 80;
            object = substr(plist, obj_offset + 1, obj_offset + obj_size);
          }
          keys[i] = object;
        }
      }

      off = index + 1;
      values = make_list();

       # Going through the dictionary to get the keys
      for (i = 0; i < dict_size; i++) {
        index = i + off;
        pos = ord(plist[index]) * item_size;

        if (item_size == 2)
          obj_offset = getword(blob: offset_table, pos: pos);
        else if (item_size == 1)
          obj_offset = ord(offset_table[pos]);

        object_starter = plist[obj_offset];

        # Handle Strings
        if (hexstr(object_starter) =~ "^5") {
          if (hexstr(object_starter) == "5f") {
            # Currently we just ignore the first one as there shouldn't be anything bigger than 0xFF
            # in our cases
            obj_size = ord(plist[obj_offset + 2]);
            object = substr(plist, obj_offset + 3, obj_offset + 2 + obj_size);
          } else {
            obj_size = ord(object_starter) - 80;
            object = substr(plist, obj_offset + 1, obj_offset + obj_size);
          }
          values[i] = object;
        } else {
          # nb: Non-strings are not interesting for us
          values[i] = "";
        }
      }
    }
  }

  if (max_index(keys) > 0) {
    objects = make_array();
    for (i = 0; i < max_index(keys); i++) {
      # nb: Skip non-strings
      if (values[i] == "")
        continue;

      objects[keys[i]] = values[i];
      set_kb_item(name: "apple/airplay/" + port + "/objects", value: keys[i] + "###---###" + values[i]);
    }
  }
}

if (objects) {
  report = '\n\nThe following information was extracted:\n\n';
  report += text_format_table(array: objects, columnheader: make_list("Key", "Value"));
}

report = "An AirPlay service is running at this port." + report;

log_message(port: port, data: report);

exit(0);
