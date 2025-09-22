# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143661");
  script_version("2024-07-19T15:39:06+0000");
  script_tag(name:"last_modification", value:"2024-07-19 15:39:06 +0000 (Fri, 19 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-03-31 08:28:25 +0000 (Tue, 31 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DrayTek Vigor Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of DrayTek Vigor devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

fingerprint["fc01b524d58083bbabf115d02755052c"] = "130";
fingerprint["6749372bdea55e2ff3c5f631c13e945f"] = "165";
fingerprint["bab52c2d280cc70bc4a1d3b7ac4bc4c8"] = "2120";
fingerprint["ee81f6ddea65d4568d36f0fbbc6451ef"] = "2132F";
fingerprint["4f03017fc1432854ddaec16738e6c7f6"] = "2133";
fingerprint["b7fef4d33af3e68d909dd2dad0f35bc3"] = "2133";
fingerprint["1f76a6bfff7bd08fdb8fe063711dcb6c"] = "2135";
fingerprint["6ca245b1e709ed112d8d23e49e6dced3"] = "2135";
fingerprint["1d61282d0995f0b63b28840448ff31d7"] = "2620";
fingerprint["b21b90d0e71ce863cf00a2f05c41bd78"] = "2620"; # /images/login.png
fingerprint["4172705528245ca522368b8a75a06ac1"] = "2760";
fingerprint["b05c6d98c3118430f9c3be10a22681fa"] = "2762";
fingerprint["5ee3a08ba6d03a40fb2bc7f7cf1fde09"] = "2762"; # /images/login1.png
fingerprint["5f3959c010e8e7cc04b0c0f206935e90"] = "2765";
fingerprint["86b03c9aa8e781971fbc8fed97d27054"] = "2765"; # /images/login1_5.png
fingerprint["22c339ed75473b33a569297348c8cac6"] = "2765"; # /images/weblogin.png
fingerprint["eab44a2839f45dfbe95d6d89c5df491b"] = "2832";
fingerprint["9fa6a67cb3a73b4645a93b82025ff12e"] = "2832"; # /images/login1.png
fingerprint["302e9f953b93a19565156d8551576600"] = "2860"; # /images/login.png
fingerprint["75c151788f32d1f4a61400b2248453b0"] = "2860";
fingerprint["86d93580f67d70e80cc079593ab88592"] = "2860"; # /images/login1.png
fingerprint["7e569db3f217067016a29aa245fd2332"] = "2862";
fingerprint["014b63f7ce352ed6b20ee98304700cf4"] = "2862";
fingerprint["632c09721ec5026ae4d31501dfc5c5fc"] = "2862";
fingerprint["64cf9c2bcb1c2b1800d9dedcee63d8cb"] = "2862";
fingerprint["01a62ce514d84de1d3f83e9f6c144fb0"] = "2862"; # /images/weblogin.png
fingerprint["7b562c87d45cabc36591098777962cf5"] = "2865";
fingerprint["21f8e1de0330aa67d602bf18000bb2eb"] = "2865"; # /images/weblogin.png
fingerprint["522fcb20f5cfa4dbbd760c76989d49c9"] = "2865";
fingerprint["593a9bb0503491870ff4ed8ee39e490c"] = "2912";
fingerprint["1f187cf87c5c57c043e259e0401dc90a"] = "2915";
fingerprint["fed299654275131765a94ba7f864cf82"] = "2915";
fingerprint["2c21bd8492de50153b3e32dea7a5fab3"] = "2915"; # /images/weblogin.png
fingerprint["acaa42a11fb6fe92d1e6b0454df076aa"] = "2925";
fingerprint["f530aff4ad44eb41667d9638dfcf2041"] = "2925";
fingerprint["50b4eddc6f12662e7e376cc78795b209"] = "2926";
fingerprint["641cd48348f0189013a37ceeb462e1ac"] = "2926";
fingerprint["4677f5d3b33394125725d3d3af87f24d"] = "2926";
fingerprint["b0272d7b994352daa6f1505b62df0d1b"] = "2926"; # /images/login.png
fingerprint["1c91301ed3a8243e7f57fa6f1ac1995a"] = "2926"; # /images/weblogin.png
fingerprint["e76043732d84479a9b8cd007a51c5a1c"] = "2926 plus"; # /images/weblogin.png
fingerprint["067a7f7be69c971597f8709fbc326c31"] = "2927";
fingerprint["dcb20a6aef3e232e04f8e42f5d222346"] = "2927";
fingerprint["dcb20a6aef3e232e04f8e42f5d222346"] = "2927"; # /images/login_f1.png
fingerprint["cd9845ab5f472db67f569b7167c4ddc0"] = "2952";
fingerprint["6c74369fb95b8f140a14c35683359db2"] = "2952";
fingerprint["bf458473b7263ec0f9e9460e83134ddb"] = "2952"; # /images/weblogin.png
fingerprint["08b1c6970d62ffba7397bd50e757c4c9"] = "3220";
fingerprint["73b20430dcfc6a626026de62740154c8"] = "BX 2000";

# nb: This is needed to handle cases where 2 or 3 model images are contained in the same weblogin.png, and the difference is made via the 'issecmodel' JS variable
fingerprint_issec["22c339ed75473b33a569297348c8cac6"] = "2766";
fingerprint_issec["522fcb20f5cfa4dbbd760c76989d49c9"] = "2866";

# nb: This is needed to handle cases where 2 or 3 model images are contained in the same weblogin.png, and the difference is made via the 'isfiber' JS variable
fingerprint_isfiber["6ca245b1e709ed112d8d23e49e6dced3"] = "2135F";

port = http_get_port(default: 443);

url = "/";
res = http_get_cache(port: port, item: url);
url2 = "/weblogin.htm";
res2 = http_get_cache(port: port, item: url2);

concl = "";
conclUrl = "";
found = 0;

if ("<title>Vigor " >< res && (concl = egrep(pattern: 'var isomorphicDir = "[^/]+/sc/"', string: res, icase: TRUE)) && res =~ "Server\s*:\s*DWS") {
  found++;
  concl = "    " + chomp(concl);
  conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

if ((conc = eregmatch(pattern: "<title>Vigor Login Page</title>", string: res2)) && "DrayTek" >< res2) {
  found++;
  if (concl)
    concl += '\n';
  concl += "    " + chomp(conc[0]);
  if (conclUrl)
    conclUrl += '\n';
  conclUrl = "    " + http_report_vuln_url(port: port, url: url2, url_only: TRUE);
}

# nb: Seems that the vast majority of targets with this Header are honeypots
# Server: DrayTek/Vigor2130 UPnP/1.0 miniupnpd/1.0
if (conc = egrep(pattern: "Server\s*:\s*DrayTek/Vigor[^ ]+", string: res, icase: TRUE)) {
  found++;
  if (concl)
    concl += '\n';
  concl += "    " + chomp(conc);
  conclUrl = "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
}

if (found > 0) {
  model = "unknown";
  version = "unknown";

  set_kb_item(name: "draytek/vigor/detected", value: TRUE);
  set_kb_item(name: "draytek/vigor/http/detected", value: TRUE);
  set_kb_item(name: "draytek/vigor/http/port", value: port);

  mod = eregmatch(pattern: "<title>Vigor ([0-9A-Z]+)", string: res);
  if (!isnull(mod[1]) && "Vigor Login Page" >!< res) {
    model = mod[1];
      if (concl)
      concl += '\n';
    concl += "    " + chomp(mod[0]);
  }

  if (model == "unknown") {
    mod = eregmatch(pattern: "Server\s*:\s*DrayTek/Vigor([0-9A-Z]+)", string: res);
    if (!isnull(mod[1])) {
      model = mod[1];
      if (concl)
        concl += '\n';
      concl += "    " + chomp(mod[0]);
    }
  }

  if (model == "unknown") {
    # >Vigor 3910<
    # >Vigor1000B<
    mod = eregmatch(pattern: ">Vigor\s*([0-9A-Z]+)<", string: res2);
    if (!isnull(mod[1])) {
      model = mod[1];
      if (concl)
        concl += '\n';
      concl += "    " + chomp(mod[0]);
    }
  }

  if (version == "unknown") {
    # fwver:"4.4.2.1"
    # fwver:"4.4.2_BT"
    vers = eregmatch(pattern: 'fwver:"([0-9.]+([_A-Za-z]+)?)"', string: res2);
    if (!isnull(vers[1])) {
      version = vers[1];
      if (concl)
        concl += '\n';
      concl += "    " + chomp(vers[0]);
    }
  }

  issecmodel = "";

  issec = eregmatch(pattern: 'issecmodel:parseInt\\("([0-9])"\\)', string: res2);
  if (!isnull(issec[1]))
    issecmodel = issec[1];

  isfiber = "";

  isfib = eregmatch(pattern: 'isfiber:parseInt\\("([0-9])"\\)', string: res2);
  if (!isnull(isfib[1]))
    isfiber = isfib[1];

  if (model == "unknown") {
    foreach url (make_list("/images/login.png", "/images/login1.png", "/images/weblogin.png", "/images/login1_5.png", "/images/login_f1.png")) {
      req = http_get(port: port, item: url);
      res = http_keepalive_send_recv(port: port, data: req);

      if (res && res !~ "^HTTP/1\.[01] 404") {
        body = http_extract_body_from_response(data: res);
        md5 = hexstr(MD5(body));
        fp = "";
        if (issecmodel && "1" >< issecmodel)
          fp = fingerprint_issec[md5];
        else if (isfiber && "1" >< isfiber)
          fp = fingerprint_isfiber[md5];
        else
          fp = fingerprint[md5];
        # nb: In some cases the png has several identical model images, therefore even if isfiber or issecmodel is set, we can try to fallback to the main fingerprint dictionary
        if (!fp)
          fp = fingerprint[md5];
        if (fp) {
          model = fp;
          if (conclUrl)
            conclUrl += '\n';
          conclUrl += "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
          break;
        }
      }
    }
  }
  if (model == "unknown") {
    url = "/cgi-bin/mainfunction.cgi";

    # action=get_ui_model&rtick=1721055499744
    data = "action=get_ui_model&rtick=" + unixtime();
    req = http_post_put_req(port: port, url: url, data: data);
    res = http_keepalive_send_recv(port: port, data: req);
    # Vigor3900
    # Vigor300B
    # Vigor2960
    mod = eregmatch(pattern: "Vigor(.+)", string: res);
    if (!isnull(mod[1])) {
      model = mod[1];
      if (concl)
        concl += '\n';
      concl += "    " + chomp(mod[0]);
      if (conclUrl)
        conclUrl += '\n';
      conclUrl += "    " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    }
  }

  set_kb_item(name: "draytek/vigor/http/" + port + "/model", value: model);
  set_kb_item(name: "draytek/vigor/http/" + port + "/version", value: version);
  set_kb_item(name: "draytek/vigor/http/" + port + "/concluded", value: concl);
  set_kb_item(name: "draytek/vigor/http/" + port + "/concludedUrl", value: conclUrl);
}

exit(0);
