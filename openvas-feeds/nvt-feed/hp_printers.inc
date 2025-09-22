# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# IMPORTANT:
# For HTTP status code response checks like e.g. "HTTP/1\.[01] 200" don't include a "^" in front as
# such devices are known to not follow RFCs strictly or could show otherwise weird responses.

# @brief Returns an array containing the URL for a HP printer detection
#        as the array key and the regex to extract the type/model as the value.
#
# @note The array key might contain a pattern like e.g. (numbers incrementing
#       for multiple same URLs):
#
#       #--avoid-dup1--#
#
#       to be able to have different array keys for the same URL.
#       Make sure to strip such patterns away with ereg_replace
#       in the VT calling this function.
#
# @return An array as described in the function description.
#
function get_hp_detect_urls() {

  local_var hp_detect_urls;

  hp_detect_urls = make_array();

  # HP LaserJet P2015 a.o.
  hp_detect_urls["/info_deviceStatus.html"]                             = "<title>HP (LaserJet [^ ]+) Series";

  # HP Color LaserJet 2840 a.o.
  hp_detect_urls["/hp/device/"]                                         = '<title> HP Color (LaserJet [^\n ]+)';

  # HP LaserJet P3005 a.o.
  hp_detect_urls["/hp/device/#--avoid-dup1--#"]                         = '<title>\\s*HP (LaserJet (Pro )?(MFP )?[^&\n ]+)';

  # HP Color LaserJet CP2025n a.o.
  hp_detect_urls["/info_deviceStatus.html?tab=Status"]                  = "<title>HP Color (LaserJet [^&]+)";

  # HP LaserJet 400 M401n a.o.
  hp_detect_urls["/info_deviceStatus.html?"]                            = "<title>HP (LaserJet [^&]+)";

  # LaserJet 3600 a.o.
  hp_detect_urls["/index_top.htm"]                                      = string("(HP (LaserJet [^\n ]+)|HP Color (LaserJet [^\n ]+)|(DesignJet [^ ]+)|(psc [^ ]+) series)");

  # K5400 a.o.
  hp_detect_urls["/index.htm?cat=info&page=printerInfo"]                = string("((Officejet Pro [^& ]+)|(Officejet [^\n ]+))");

  # HP Color LaserJet Flow MFP 680 a.o.
  hp_detect_urls["/hp/device/InternalPages/Index?id=ConfigurationPage"] = '<strong id="ProductName">HP ?([^&<]+)';

  # HP Color LaserJet M651 a.o.
  hp_detect_urls["/"]                                                   = '<strong class="product">HP ?([^&<]+)';

  # HP Latex 315 a.o.
  hp_detect_urls["/hp/jetdirect/index.html"]                            = "<h1>HP (Latex [0-9]+)";

  # HP Color LaserJet CM4540 MFP a.o.
  hp_detect_urls["/hp/jetdirect/index.html#--avoid-dup1--#"]            = "<h1>HP (Color LaserJet [^<]+)";

  # HP PageWide Pro 477 a.o.
  hp_detect_urls["/DevMgmt/ProductConfigDyn.xml"]                       = "<dd:MakeAndModel>HP (PageWide Pro [^<]+)";

  # HP PageWide 352dw a.o
  hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup1--#"]       = "<dd:MakeAndModel>HP (PageWide [^<]+)";

  # HP Deskjet 2540 a.o.
  hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup2--#"]       = "<dd:MakeAndModel>(Deskjet [^<]+)";

  # HP ENVY 120 series a.o.
  hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup3--#"]       = "<dd:MakeAndModel>(Envy [^<]+)";

  # HP Ink Tank Wireless 410 series a.o.
  hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup4--#"]       = "<dd:MakeAndModel>(Ink Tank [^<]+)";

  # HP Photosmart 5510 series a.o.
  hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup5--#"]       = "<dd:MakeAndModel>(Photosmart [^<]+)";

  # HP Smart Tank Wireless 450 series a.o.
  hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup6--#"]       = "<dd:MakeAndModel>HP (Smart Tank [^<]+)";

  # HP Smart Tank Wireless 450 series a.o.
  hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup7--#"]       = "<dd:MakeAndModel>(Smart Tank [^<]+)";

  # HP OfficeJet Pro 8210 series a.o.
  hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup8--#"]       = "<dd:MakeAndModel>HP (OfficeJet [^<]+)";

  # HP Color Laser MFP 179 a.o.
  hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup9--#"]       = "<dd:MakeAndModel>HP (Color Laser [^<]+)";

  hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup10--#"]      = "<dd:MakeAndModel>HP (LaserJet [^<]+)";

  # HP OfficeJet Pro 6978 series a.o.
  hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup11--#"]      = "<dd:MakeAndModel>(OfficeJet [^<]+)";

  # HP Color Laser MFP 179 a.o.
  hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup12--#"]      = "<dd:MakeAndModel>HP (Laser [^<]+)";

  # HP Color LaserJet Pro M454nw a.o
  hp_detect_urls["/DevMgmt/ProductConfigDyn.xml#--avoid-dup13--#"]      = "<dd:MakeAndModel>HP (Color LaserJet [^<]+)";

  # HP LaserJet 700 color MFP M775 a.o.
  hp_detect_urls["/hp/device/SignIn/Index"]                             = '"product">HP (LaserJet [^<]+)';

  # Unknown older HP printers
  hp_detect_urls["/Navmenu.html"]                                       = 'value="Web JetAdmin';

  # HP Color LaserJet Pro 4201 a.o.
  hp_detect_urls["/cdm/system/v1/identity"]                             = '"base"\\s*:\\s*"HP Color (LaserJet [^"]+)';

  # Detection string from dont_print_on_printers.nasl. TBD: Include here?
  # if( "<title>Hewlett Packard</title>" >< banner || egrep( pattern:"<title>.*LaserJet.*</title>", string:banner, icase:TRUE ) || "HP Officejet" >< banner || "server: hp-chai" >< tolower( banner ) || ( "Server: Virata-EmWeb/" >< banner && ( "HP" >< banner || "printer" >< banner ) ) ) {

  return hp_detect_urls;
}

function check_hp_default_login( model, port ) {

  local_var model, port, HP, host, req, buf;

  HP = hp_login_details( model:model );
  if( ! HP ) return FALSE;

  if( HP["no_default_auth"] ) {
    if( HP["req_type"] == "GET" ) {
      if( HP["req_auth"] == "BASIC" ) {

        host = http_host_name( port:port );
        req = string( "GET ", HP["login_url"], " HTTP/1.1\r\n",
                      "Host: ", host, "\r\n" );
        buf = http_send_recv( port:port, data:req + '\r\n', bodyonly:FALSE );
        hp_error_exit( buf:buf );

        if( ereg( pattern:HP["http_status"], string:buf ) ) {
          if( eregmatch( pattern:HP["login_success"], string:buf ) ) {
            return 2;
          }
        }
      }
    }
  }
}

# @brief Returns an array with the details about the login/restricted pages to check authentication for depending
#        on the model provided
#
# @param model The model to return the details for
#
# @note The "http_status" and "login_success" entries below are used in ereg() or eregmatch() calls
#       and thus special regex chars like a dot needs to be escaped. Also see the important note on
#       the top of this include.
#
# @return An array containing the needed information for authentication checks
#
#         ret_array["req_type"]        = the HTTP request type (GET/POST)
#         ret_array["login_url"]       = the URL to check authentication
#         ret_array["req_auth"]        = the kind of authentication (currently BASIC)
#         ret_array["no_default_auth"] = boolean if default no authentication is set
#         ret_array["http_status"]     = the HTTP status to expect from a successful authentication as a regex
#         ret_array["login_success"]   = the regex to check for in case of successful authentication
#
function hp_login_details( model ) {

  local_var model;
  local_var hp_printer;

  if(!model) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#model#-#hp_login_details");
    return;
  }

  hp_printer = make_array();

  if(model =~ "LaserJet 100 colorMFP M175nw" ||
     model =~ "LaserJet P2015"               ||
     model =~ "LaserJet CP2025n"             ||
     model =~ "LaserJet CP1515n"             ||
     model =~ "LaserJet M1522nf MFP"         ||
     model =~ "LaserJet M1536dnf MFP"        ||
     model =~ "LaserJet M2727nf MFP"         ||
     model =~ "LaserJet 2605dtn"             ||
     model =~ "LaserJet 2605dn"              ||
     model =~ "LaserJet 3055"                ||
     model =~ "LaserJet CM1312nfi"           ||
     model =~ "LaserJet CM2320fxi"           ||
     model =~ "LaserJet CM1415fn"            ||
     model =~ "LaserJet CM2320nf"            ||
     model =~ "LaserJet 400 color M451dn"    ||
     model =~ "LaserJet 400 M401n"           ||
     model =~ "LaserJet 400 M401dn") {

    hp_printer["req_type"] = "GET";
    hp_printer["login_url"] = "/set_config_networkIP.html";
    hp_printer["req_auth"] = "BASIC";
    hp_printer["no_default_auth"] = "TRUE";

    hp_printer["http_status"] = "HTTP/1\.[01] 200";
    hp_printer["login_success"] = 'label for="IPAddr1">';

    return hp_printer;
  }

  else if(model =~ "LaserJet 2840") {

    hp_printer["req_type"] = "GET";
    hp_printer["login_url"] = "/hp/device/set_config_networkIP.html";
    hp_printer["req_auth"] = "BASIC";
    hp_printer["no_default_auth"] = "TRUE";

    hp_printer["http_status"] = "HTTP/1\.[01] 200";
    hp_printer["login_success"] = "This table contains the Network IP heading";

    return hp_printer;
  }

  else if(model =~ "LaserJet 5100"   ||
          model =~ "LaserJet 5000"   ||
          model =~ "LaserJet 4000"   ||
          model =~ "LaserJet 4050"   ||
          model =~ "LaserJet 3800"   ||
          model =~ "LaserJet 3700"   ||
          model =~ "LaserJet 3600"   ||
          model =~ "LaserJet 3500"   ||
          model =~ "LaserJet 2200"   ||
          model =~ "LaserJet 3550"   ||
          model =~ "LaserJet 3030"   ||
          model =~ "LaserJet 2300"   ||
          model =~ "LaserJet 8150"   ||
          model =~ "LaserJet 5800"   ||
          model =~ "Designjet 800PS" ||
          model =~ "DesignJet 800"   ||
          model =~ "LaserJet 2550"   ||
          model =~ "LaserJet 1320"   ||
          model =~ "Designjet 500"   ||
          model =~ "DesignJet 1055CM") {

    hp_printer["req_type"] = "GET";
    hp_printer["login_url"] = "/tcp_param.htm";
    hp_printer["req_auth"] = "BASIC";
    hp_printer["no_default_auth"] = "TRUE";

    hp_printer["http_status"] = "HTTP/1\.[01] 200";
    hp_printer["login_success"] = "This table displays the TCP/IP configuration items";

    return hp_printer;
  }

  else if(model =~ "LaserJet 4250"    ||
          model =~ "LaserJet 4600"    ||
          model =~ "LaserJet 4650"    ||
          model =~ "designjet 5500ps" ||
          model =~ "LaserJet 4200"    ||
          model =~ "LaserJet 4730mfp" ||
          model =~ "LaserJet 4730"    ||
          model =~ "LaserJet CM4730"  ||
          model =~ "LaserJet P2055dn" ||
          model =~ "Color LaserJet M651" ||
          model =~ "LaserJet 2430") {

    hp_printer["req_type"] = "GET";
    hp_printer["login_url"] = "/hp/jetdirect/tcp_param.htm";
    hp_printer["req_auth"] = "BASIC";
    hp_printer["no_default_auth"] = "TRUE";

    hp_printer["http_status"] = "HTTP/1\.[01] 200";
    hp_printer["login_success"] = "This table displays the TCP/IP configuration items";

    return hp_printer;
  }

  else if(model =~ "psc 2500") {

    hp_printer["req_type"] = "GET";
    hp_printer["login_url"] = "/uvl_gen_settings.htm";
    hp_printer["req_auth"] = "BASIC";
    hp_printer["no_default_auth"] = "TRUE";

    hp_printer["http_status"] = "HTTP/1\.[01] 200";
    hp_printer["login_success"] = "This table is used to display the network protocol links/tabs";

    return hp_printer;
  }

  else if(model =~ "Officejet Pro K5400"  ||
          model =~ "Officejet Pro K5400"  ||
          model =~ "Officejet Pro L7600"  ||
          model =~ "Officejet Pro 8500"   ||
          model =~ "Officejet 7000 E809a") {

    hp_printer["req_type"] = "GET";
    hp_printer["login_url"] = "/index.htm?cat=network&page=wiredIfc&adaptorID=0";
    hp_printer["req_auth"] = "BASIC";
    hp_printer["no_default_auth"] = "TRUE";

    hp_printer["http_status"] = "HTTP/1\.[01] 200";
    hp_printer["login_success"] = 'id="alt_dnsserver1"';

    return hp_printer;
  }

  else if(model =~ "Officejet 4500") {

    hp_printer["req_type"] = "GET";
    hp_printer["login_url"] = "/index.htm?cat=network&page=wirelessIfc";
    hp_printer["req_auth"] = "BASIC";
    hp_printer["no_default_auth"] = "TRUE";

    hp_printer["http_status"] = "HTTP/1\.[01] 200";
    hp_printer["login_success"] = 'id="alt_dnsserver1"';

    return hp_printer;
  }

  # Officejet Pro 8600 N911g
  else if(model =~ "Officejet Pro 8600") {

    hp_printer["req_type"] = "GET";
    hp_printer["login_url"] = "/webApps/Wired/ipV4.htf";
    hp_printer["req_auth"] = "BASIC";
    hp_printer["no_default_auth"] = "TRUE";

    hp_printer["http_status"] = "HTTP/1\.[01] 200";
    # <?hp te.includeSubPage("/webApps/Wired/ip4.htf") ?>
    hp_printer["login_success"] = "<?hp te\.includeSubPage";

    return hp_printer;
  }

  set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#hp_login_details(): Unknown/not supported printer model '" + model + "' passed.");

  return;
}

function hp_error_exit( buf ) {

  local_var buf;

  if( ! buf || ereg( pattern:"HTTP/1\.[01] (404|401|500)", string:buf ) )
    exit( 0 );

  return TRUE;
}
