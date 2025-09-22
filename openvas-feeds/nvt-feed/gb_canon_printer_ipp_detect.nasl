# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.171370");
  script_version("2025-06-09T05:41:14+0000");
  script_tag(name:"last_modification", value:"2025-06-09 05:41:14 +0000 (Mon, 09 Jun 2025)");
  script_tag(name:"creation_date", value:"2025-04-03 11:20:37 +0000 (Thu, 03 Apr 2025)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Canon Printer Detection (IPP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2025 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_ipp_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("IPP/banner");
  script_exclude_keys("cups/banner");

  script_tag(name:"summary", value:"IPP based detection of Canon printer devices.");

  exit(0);
}

include("port_service_func.inc");

port = service_get_port(default: 631, proto:"ipp");

if (!port)
  exit(0);

banner = get_kb_item("Canon/banner");
method = get_kb_item("ipp/" + port + "/extra-used-method");

# nb: We try to restrict the detection to actual printers
# - many printers have 'Server: CANON HTTP Server' header in the HTTP reply
# - some more modern ones lack the header or do not reply to HTTP at all on 631.
# - the IPP method is an additional check as CUPS replies to 'CUPS-Get-Printers'
if (!banner && (!method || method != "Get-Printer-Attributes"))
  exit(0);

if (!printers = get_kb_list("ipp/" + port + "/printer"))
  exit(0);

foreach printer_name(printers) {
  printer_info = get_kb_item("ipp/" + port + "/" + printer_name + "/printer-info");

  if (!printer_info || (printer_info !~ "^Canon" && "http://www.canon.com" >!< printer_info))
    continue;

  set_kb_item(name: "canon/printer/detected", value: TRUE);
  set_kb_item(name: "canon/printer/ipp/detected", value: TRUE);
  set_kb_item(name: "canon/printer/ipp/port", value: port);

  concluded = "    Printer info: " +  printer_info;
  printer_mod = get_kb_item("ipp/" + port + "/" + printer_name + "/printer-make-and-model");
  # nb: " Series" is removed in the consolidation, therefore we keep all the space-separated elements
  # CNMF645C
  # Canon MF750C Series
  # CNiR-ADV C250/350
  # Canon iR-ADV C3926
  # Canon i-SENSYS X C1533i II
  mod = eregmatch(pattern: "^(Canon |CN)((iR-ADV )?([^/]+)).*", string: printer_mod, icase: TRUE);

  if (!isnull(mod[2])) {
    model = mod[2];
    concluded += '\n    Printer make and model: ' + printer_mod;
    set_kb_item(name: "canon/printer/ipp/" + port + "/model", value: model);
  }

  vers = get_kb_item("ipp/" + port + "/" + printer_name + "/printer-firmware-string-version");

  if (!isnull(vers)) {
    concluded += '\n    Printer firmware string version: ' + vers;
    set_kb_item(name: "canon/printer/ipp/" + port + "/fw_version", value: vers);
  }

  set_kb_item(name: "canon/printer/ipp/" + port + "/concluded", value: concluded);

}

exit(0);
