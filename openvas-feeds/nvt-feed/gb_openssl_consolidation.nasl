# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145462");
  script_version("2025-07-09T05:43:50+0000");
  script_tag(name:"last_modification", value:"2025-07-09 05:43:50 +0000 (Wed, 09 Jul 2025)");
  script_tag(name:"creation_date", value:"2021-02-26 05:56:14 +0000 (Fri, 26 Feb 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OpenSSL Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of OpenSSL detections.");

  script_tag(name:"vuldetect", value:"Note: Depending on the install method of OpenSSL on the target
  host multiple detection and vulnerability results for the same version / installation needs to be
  expected.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_openssl_ssh_login_detect.nasl", "gb_openssl_smb_login_detect.nasl",
                      "gb_openssl_http_detect.nasl", "gb_openssl_ssh_detect.nasl",
                      "gb_openssl_library_ssh_login_detect.nasl");
  script_mandatory_keys("openssl/detected");

  script_xref(name:"URL", value:"https://openssl-library.org/");

  exit(0);
}

if (!get_kb_item("openssl/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source (make_list("http", "ssh-login", "smb-login", "ssh")) {
  install_list = get_kb_list("openssl/" + source + "/*/installs");
  if (!install_list)
    continue;

  install_list = sort(install_list);

  foreach install (install_list) {
    infos = split(install, sep: "#---#", keep: FALSE);
    if (max_index(infos) < 3)
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    install  = infos[1];
    version  = infos[2];
    concl    = infos[3];
    extra    = infos[4];
    conclurl = infos[5];

    cpe = build_cpe(value: version, exp: "^([0-9a-z.]+)", base: "cpe:/a:openssl:openssl:");
    if (!cpe)
      cpe = "cpe:/a:openssl:openssl";

    if (source == "http")
      source = "www";

    register_product(cpe: cpe, location: install, port: port, service: source);

    if (report)
      report += '\n\n';

    report += build_detection_report(app: "OpenSSL", version: version, install: install, cpe: cpe,
                                     concluded: concl, concludedUrl: conclurl, extra: extra);
  }
}

if (report)
  log_message(port: 0, data: report);

exit(0);
