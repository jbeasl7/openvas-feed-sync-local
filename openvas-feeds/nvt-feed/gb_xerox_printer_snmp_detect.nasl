# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141825");
  script_version("2025-02-18T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-02-18 05:38:27 +0000 (Tue, 18 Feb 2025)");
  script_tag(name:"creation_date", value:"2019-01-04 13:53:28 +0700 (Fri, 04 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Xerox Printer Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Xerox printer devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_snmp_info_collect.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdescr/available");

  exit(0);
}

include("dump.inc");
include("misc_func.inc");
include("snmp_func.inc");

port = snmp_get_port(default: 161);

sysdesc = snmp_get_sysdescr(port: port);
if (!sysdesc)
  exit(0);

# Some Xerox printers return a hex representative
# e.g. 58 65 72 6F 78 C2 AE 20 43 6F 6C 6F 72 20 31 30 ...
# Change back to a string and remove unprintable chars
if (sysdesc =~ "^[0-9A-F]{2} [0-9A-F]{2} [0-9A-F]{2}") {
  sysdesc = hex2str(str_replace(string: sysdesc, find: " ", replace: ""));
  sysdesc = bin2string(ddata: sysdesc, noprint_replacement: "");
}

# Xerox AltaLink C8045; SS 100.002.008.05702, ...
# nb:
# - Keep in sync with the pattern used in dont_print_on_printers.nasl
# - Case insensitive match (via "=~") is expected / done on purpose as different writings of XEROX
#   vs. Xerox has been seen
if (sysdesc =~ "^Xerox( \(R\))? ") {
  set_kb_item(name: "xerox/printer/detected", value: TRUE);
  set_kb_item(name: "xerox/printer/snmp/detected", value: TRUE);
  set_kb_item(name: "xerox/printer/snmp/port", value: port);
  set_kb_item(name: "xerox/printer/snmp/" + port + "/concluded", value: sysdesc);

  # Xerox AltaLink B8045; SS 103.008.032.23400, NC 103.008.23400, UI 103.008.23400, ME 002.002.029, CC 103.008.23400, DF 000.050.000, FI ------, FA 003.016.001, CCOS 103.002.23400, NCOS 103.002.23400, SC 015.015.013, SU 103.008.23400
  mod = eregmatch(pattern: "^Xerox(\(R\))? ([^;]+);?", string: sysdesc);

  if (!isnull(mod[2])) {
    if (";" >!< mod[0]) {
      # Likely extracted from hex response so just take the first part
      model = split(mod[2], sep: " ", keep: FALSE);
      set_kb_item(name: "xerox/printer/snmp/" + port + "/model", value: model[0]);
    } else {
      set_kb_item(name: "xerox/printer/snmp/" + port + "/model", value: mod[2]);
    }
  }

  # Xerox AltaLink C8045; SS 100.002.008.05702, NC 100.002.05702.1057305v9, UI 100.002.05702, ME 063.022.000, CC 100.002.05702, DF 007.019.000, FI 010.019.000, FA 003.012.013, CCOS 100.008.05702, NCOS 100.008.05702, SC 013.015.006, SU 100.002.05702
  # Xerox Phaser 3330; SS 61.001.01.000, NC 4.00.50.40, UI V3.61.10.37, ME V0.00.37, CCOS 6.9.P
  # Xerox(R) C235 Color MFP; SS CXLBL.081.215, kernel 5.4.90-yocto-standard, All-N-1
  vers = eregmatch(pattern: "SS ([A-Z0-9.]+),", string: sysdesc);
  if (!isnull(vers[1])) {
    set_kb_item(name: "xerox/printer/snmp/" + port + "/fw_version", value: vers[1]);
    exit(0);
  }

  # Xerox(R) B225 MFP version MXLSG.075.024 kernel 4.17.19-yocto-standard-54957bcefc94efade8bf88217aaf962a All-N-1
  vers = eregmatch(pattern: "version ([A-Z0-9.]+)", string: sysdesc);
  if (!isnull(vers[1])) {
    set_kb_item(name: "xerox/printer/snmp/" + port + "/fw_version", value: vers[1]);
    exit(0);
  }

  # Xerox Phaser 3300MFP; OS 1.50.00.14   07-16-2009, Engine 1.05.44, NIC V4.02.06(P3300MFP) 07-16-2009, PCL5e 5.93 03-19-2009, PCL6 5.94  05-11-2009, PS3 V1.99.06 04-09-2009, SPL 5.24 03-27-2006, PDF V1.00.32 02-25-2006, IBM/EPSON 5.20 02-03-2009
  # Xerox Phaser 5550DN; OS 7.92, PS 4.1.0, Eng 11.58.00, Net 37.56.03.02.2008, Adobe PostScript 3016.101 (14), PCL 5e/6 Version 7.0.1
  # Xerox Phaser 3435; OS 1.70.02.63 06-19-2009, NIC V4.01.16(P3435) 06-19-2009, Engine 1.00.60, Tray2 , Duplex 0.00.00 , PCL6 5.93  03-21-2009, PS3 V1.94.06 12-22-2008
  vers = eregmatch(pattern: "OS ([0-9.]+)[, ]", string: sysdesc);
  if (!isnull(vers[1])) {
    set_kb_item(name: "xerox/printer/snmp/" + port + "/fw_version", value: vers[1]);
    exit(0);
  }

  # Xerox WorkCentre 7556 v1 Multifunction System; System Software 061.121.225.14700, ESS 061.125.14620.LL
  # Xerox WorkCentre 6515; System 65.31.81, Controller 1.40.6, IOT 1.0.0, IOT2 4.11.0, ADF 42.0.0, Fax 104.7.0, Panel 91.6.11, Boot 11.1.200, RSEP 1.8.23
  # Xerox Phaser 3635MFP; System Software Version 20.106.02.000, Main Controller 1.06.02.00, Network Controller 4.05.49, Image Output Terminal 1.00.34, User Interface 0.035.28.067
  vers = eregmatch(pattern: "System (Software )?(Version )?([0-9.]+),", string: sysdesc);
  if (!isnull(vers[3])) {
    set_kb_item(name: "xerox/printer/snmp/" + port + "/fw_version", value: vers[3]);
    exit(0);
  }

  # Xerox Phaser 6180MFP-D; Net 11.74,ESS 200802151717,IOT 05.09.00,Boot 200706151125
  vers = eregmatch(pattern: "ESS( )?([0-9.]+),", string: sysdesc);
  if (!isnull(vers[2])) {
    set_kb_item(name: "xerox/printer/snmp/" + port + "/fw_version", value: vers[2]);
    exit(0);
  }

  # Xerox WorkCentre 3325;Sys SW Version WC3325_V51.004.05.000 JAN-10-2014,MCB V2.50.03.05 JAN-10-2014,NIC V4.03.04,IOT 1.00.33,PCL5e 6.50.02.02,PCL6 6.23.00.05,PS 4.03.01.01.00.94.09 ,IBM/EPSON 5.29.01, IP Core 6.8.P
  # Xerox Phaser 3320;Sys SW Version Phaser3320_V53.005.00.000 MAY-16-2014,MCB V2.50.04.00 MAY-16-2014,NIC V4.04.00,IOT V1.00.33,PCL5e 6.50.02.03,PCL6 6.23.00.02,PS 2.83.00.59.00.59 ,IBM/EPSON 5.29.01, IP Core 6.8.P
  vers = eregmatch(pattern: "Sys SW Version [A-Za-z0-9]+_V([0-9.]+)", string: sysdesc);
  if (!isnull(vers[1])) {
    set_kb_item(name: "xerox/printer/snmp/" + port + "/fw_version", value: vers[1]);
    exit(0);
  }

  # Xerox WorkCentre 3025; MCB V3.50.21.03     SEP-15-2021, NIC V6.01.19, IOT V1.01.09 09-02-2016, IP Core 6.9.P, SPL 5.90 05-15-2014
  # Xerox Phaser 3260; MCB V3.50.01.08     FEB-05-2015, NIC V6.01.12, IOT V1.01.07 12-10-2014, IP Core 6.9.P, PCL5e 7.18 04-21-2014, PCL6 8.02 04-29-2014, PS 4.81.01.28.01.41 04-17-2014, SPL 5.90 05-15-2014, IBM/EPSON 5.33 11-12-2013
  vers = eregmatch(pattern: "MCB( )?V?([0-9.]+)", string: sysdesc);
  if (!isnull(vers[2])) {
    set_kb_item(name: "xerox/printer/snmp/" + port + "/fw_version", value: vers[2]);
    exit(0);
  }

  # Xerox Phaser 3610; Network 80.45, Controller 201407180647, Engine 05.34.00, Boot 201305201459, PCL5 201405211042, PCL6 201405211042, POSTSCRIPT 201405211042, PDF 201405211042
  vers = eregmatch(pattern: ", ?Controller (ROM)?([0-9.]+)", string: sysdesc);
  if (!isnull(vers[2])) {
    set_kb_item(name: "xerox/printer/snmp/" + port + "/fw_version", value: vers[2]);
    exit(0);
  }

  exit(0);
} else {
  mod_oid = "1.3.6.1.2.1.25.3.2.1.3.1";
  m = snmp_get(port: port, oid: mod_oid);

  # Xerox D95 Copier-Printer v 84. 19.  0 Multifunction System
  # Xerox Color EX C60-C70 with EFI Fiery Controller;
  # Xerox D110 Copier-Printer v 84. 13.  0 Multifunction System
  # Xerox 700 Digital Color Press with EFI Fiery Controller;
  # nb: Case insensitive match (via "=~") is expected / done on purpose as different writings of
  # XEROX vs. Xerox has been seen
  if (m =~ "^Xerox ") {
    set_kb_item(name: "xerox/printer/detected", value: TRUE);
    set_kb_item(name: "xerox/printer/snmp/detected", value: TRUE);
    set_kb_item(name: "xerox/printer/snmp/port", value: port);
    set_kb_item(name: "xerox/printer/snmp/" + port + "/concluded", value: m + " via OID: " + mod_oid);

    mod = eregmatch(pattern: "Xerox (.+) (Copier|with|Digital)", string: m);
    if (!isnull(mod[1]))
      set_kb_item(name: "xerox/printer/snmp/" + port + "/model", value: mod[1]);
  }
}

exit(0);
