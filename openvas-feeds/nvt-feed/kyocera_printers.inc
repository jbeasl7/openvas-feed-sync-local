# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# IMPORTANT:
# For HTTP status code response checks like e.g. "HTTP/1\.[01] 200" don't include a "^" in front as
# such devices are known to not follow RFCs strictly or could show otherwise weird responses.

global_var ky_last_user, ky_last_pass;

# @brief Returns an array containing the URL for a Kyocera printer detection
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
function kyocera_get_detect_urls() {

  local_var kyocera_detect_urls;

  kyocera_detect_urls = make_array();

  # e.g.:
  # var ModelName="FS-1130MFP"
  # var ModelName="ECOSYS M2535dn"
  # var ModelName="FS-1370DN"
  #
  # Some TP-Link devices are using the same like e.g.:
  # var modelName="Archer C5v"
  # var modelName="TL-WR902AC"
  # and these have been excluded in these:
  # - dont_print_on_printers.nasl
  # - gb_kyocera_printer_http_detect.nasl
  kyocera_detect_urls["/"]                        = 'var ModelName="([^"]+)"';

  # HeaderStatusPC("ECOSYS P2135dn","KM144B2E","", OEMFlag, color_val);
  kyocera_detect_urls["/startwlm/Start_Wlm.htm"]  = 'HeaderStatusPC\\("([^"]+)"';

  kyocera_detect_urls["/eng/start/about.htm"]     = 'PtrVal\\[0\\] = "([^"]+)";';
  kyocera_detect_urls["/start/about.htm"]         = 'PtrVal\\[0\\] = "([^"]+)";';
  kyocera_detect_urls["/eng/status/statprn.htm"]  = 'sVal\\[0\\] = "([^"]+)";';
  kyocera_detect_urls["/eng/status/statprn1.htm"] = 'sVal\\[0\\] = "([^"]+)";';

  # var ModelName = Array("ECOSYS P2135dn");
  kyocera_detect_urls["/DeepSleep.js"]            = 'var ModelName\\s*=\\s*Array\\("([^"]+)"';

  # _pp.f_getPrinterModel = 'TASKalfa 5053ci';
  kyocera_detect_urls["/js/jssrc/model/startwlm/Start_Wlm.model.htm?arg1=&arg2=&arg3=&arg4=&arg5=&arg6=&arg8=&arg9=&arg10=0&arg11="] = "_pp.f_getPrinterModel = '([^']+)';";

  # _pp.model = 'TASKalfa 2552ci';
  kyocera_detect_urls["/js/jssrc/model/dvcinfo/dvcconfig/DvcConfig_Config.model.htm?arg1=0"] = "_pp.model = '([^']+)';";

  return kyocera_detect_urls;
}

function kyocera_get_default_logins() {

  return make_list("none:admin00",
                   "Admin:admin00",
                   "admin00:admin00",
                   "Admin:Admin",
                   "admin:admin",
                   "5200:5200",
                   "root:root",
                   "2800:2800",
                   "3000:3000",
                   "admin:none",
                   "3500:3500",
                   "4000:4000",
                   "2500:2500",
                   "/:admin00",
                   "none:PASSWORD");
}

function kyocera_check_default_login(model, port) {

  # nb: ky_last_user and ky_last_pass are global vars
  local_var model, port;
  local_var ky, logins, host, useragent, _login, user_pass;
  local_var username, password, login_data, len, req, c_buf;

  if(!model) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#model#-#kyocera_check_default_login");
    return;
  }

  if(!port) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#kyocera_check_default_login");
    return;
  }

  # nb: Model is normally passed lowercase via the calling VT. We're making it lowercase just to be sure...
  model = tolower(model);

  ky = kyocera_get_login_details(model:model);
  if(!ky)
    return FALSE;

  logins = kyocera_get_default_logins();

  host = http_host_name(port:port);
  useragent = http_get_user_agent();

  foreach _login(logins) {

    user_pass = split(_login, sep:":", keep:FALSE);
    username = user_pass[0];
    password = user_pass[1];

    if(username == "none")
      username = "";

    if(password == "none")
      password = "";

    login_data = ky["login_data"];

    if(login_data) {
      login_data = str_replace(string:login_data, find:"%%%USERNAME%%%", replace:username);
      login_data = str_replace(string:login_data, find:"%%%PASSWORD%%%", replace:password);
    }

    len = strlen(login_data);

    if(ky["req_type"] == "POST") {

       req = string("POST ", ky["login_url"], " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n",
                    "User-Agent: ", useragent, "\r\n",
                    "Content-Type: application/x-www-form-urlencoded\r\n",
                    "Content-Length: ", len, "\r\n",
                    "Connection: close\r\n",
                    "\r\n",
                    login_data);
    }

    else if(ky["req_type"] == "GET") {

      if(ky["req_auth"] == "BASIC") {

        userpass = username + ":" + password;
        userpass64 = base64(str:userpass);

        req = string("GET ", ky["login_url"], " HTTP/1.1\r\n",
                     "Host: ", host, "\r\n");

        c_buf = http_send_recv(port:port, data:req + '\r\n', bodyonly:FALSE);
        kyocera_error_exit(buf:c_buf);

        if(c_buf !~ "HTTP/1\.[01] 401" && c_buf !~ "HTTP/1\.[01] 302")
          return 2; # setup without auth

        req += string("Authorization: Basic ", userpass64, "\r\n\r\n");
      }
    }

    buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
    kyocera_error_exit(buf:buf);

    if(ereg(pattern:ky["http_status"], string:buf)) {
      if(eregmatch(pattern:ky["login_success"], string:buf)) {
        ky_last_user = username;
        ky_last_pass = password;
        return 1;
      }
    }
  }
  return 0;
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
#         ret_array["http_status"]     = the HTTP status to expect from a successful authentication as a regex
#         ret_array["login_success"]   = the regex to check for in case of successful authentication
#
function kyocera_get_login_details(model) {

  local_var model;
  local_var ky_printer;

  if(!model) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#model#-#kyocera_get_login_details");
    return;
  }

  # nb: Same as in kyocera_check_default_login()
  model = tolower(model);

  ky_printer = make_array();

  if(model =~ "fs-1030d") {

    ky_printer["req_type"] = "GET";
    ky_printer["login_url"] = "/eng/basic/SecAcct.htm";
    ky_printer["req_auth"] = "BASIC";
    ky_printer["http_status"] = "HTTP/1\.[01] 200";
    ky_printer["login_success"] = "form0\.NEWPASS\.value";

    return ky_printer;
  }

  else if(model =~ "fs-9530dn"        ||
          model =~ "km-2560"          ||
          model =~ "km-2050"          ||
          model =~ "cd_1240_dc_2240"  ||
          model =~ "fs-2000d"         ||
          model =~ "fs-9130dn"        ||
          model =~ "km-3060"          ||
          model =~ "km-c4035e"        ||
          model =~ "fs-3820n"         ||
          model =~ "fs-3900dn"        ||
          model =~ "taskalfa_221"     ||
          model =~ "2gr-50"           ||
          model =~ "km-c2525e"        ||
          model =~ "km-c2525e\(j\)"   ||
          model =~ "a3-3140_314g"     ||
          model =~ "a3-2640_264g"     ||
          model =~ "taskalfa_181\(j\)"||
          model =~ "chc-2650_265g-05" ||
          model =~ "km-2550"          ||
          model =~ "km-1650\(j\)"     ||
          model =~ "km-1820"          ||
          model =~ "fs-C5030n"        ||
          model =~ "km-4050"          ||
          model =~ "fs-C5015n"        ||
          model =~ "km-5050") {

    ky_printer["req_type"] = "GET";
    ky_printer["login_url"] = "/basic/SecAcct.htm";
    ky_printer["req_auth"] = "BASIC";
    ky_printer["http_status"] = "HTTP/1\.[01] 200";
    ky_printer["login_success"] = "form0\.NEWPASS\.value";

    return ky_printer;
  }

  else if(model =~ "fs-9500dn"                ||
          model =~ "fs-1920"                  ||
          model =~ "fs-9100dn"                ||
          model =~ "fs-1900"                  ||
          model =~ "fs-1000"                  ||
          model =~ "fs-1010"                  ||
          model =~ "printing_system_\(u\)_30" ||
          model =~ "printing_system_\(n\)_35" ||
          model =~ "printing_system_\(u\)_50" ||
          model =~ "printing_system_\(q\)_45" ||
          model =~ "km-2530"                  ||
          model =~ "km-3035\(j\)"             ||
          model =~ "km-3035"                  ||
          model =~ "km-5035"                  ||
          model =~ "km-5035\(j\)"             ||
          model =~ "fs-3800"                  ||
          model =~ "chc-3035"                 ||
          model =~ "km-3530"                  ||
          model =~ "a4_cr-16ppm-04"           ||
          model =~ "km-2030"                  ||
          model =~ "fs-9120dn"                ||
          model =~ "fs-9520dn"                ||
          model =~ "fs-1300d"                 ||
          model =~ "fs-6020"                  ||
          model =~ "chc-4035"                 ||
          model =~ "km-2531\(j\)"             ||
          model =~ "fs-1020d"                 ||
          model =~ "fs-1120d") {

    ky_printer["req_type"] = "GET";
    ky_printer["login_url"] = "/eng/security/main.htm";
    ky_printer["req_auth"] = "BASIC";
    ky_printer["http_status"] = "HTTP/1\.[01] 200";
    ky_printer["login_success"] = "The Admin password controls access";

    return ky_printer;
  }

  else if(model =~ "fs-6025mfp"     ||
          model =~ "taskalfa_300i"  ||
          model =~ "fs-1128mfp"     ||
          model =~ "fs-c5250dn"     ||
          model =~ "fs-c5200dn"     ||
          model =~ "taskalfa_400ci" ||
          model =~ "fs-1135mfp"     ||
          model =~ "fs-1370dn"      ||
          model =~ "fs-c5100dn"     ||
          model =~ "fs-c2126mfp"    ||
          model =~ "fs-1028mfp"     ||
          model =~ "fs-c5150dn"     ||
          model =~ "fs-4020dn"      ||
          model =~ "fs-3925dn"      ||
          model =~ "fs-2020d"       ||
          model =~ "taskalfa_255"   ||
          model =~ "fs-3920dn"      ||
          model =~ "fs-1035mfp"     ||
          model =~ "fs-c5350dn"     ||
          model =~ "fs-c2126mfp\+"  ||
          model =~ "fs-c5300dn"     ||
          model =~ "fs-c5400dn"     ||
          model =~ "fs-3540mfp"     ||
          model =~ "fs-c8020mfp"    ||
          model =~ "km-2810"        ||
          model =~ "taskalfa_420i"  ||
          model =~ "taskalfa_300ci" ||
          model =~ "fs-c2626mfp"    ||
          model =~ "fs-3140mfp"     ||
          model =~ "fs-3640mfp"     ||
          model =~ "fs-c8025mfp"    ||
          model =~ "fs-c2026mfp\+"  ||
          model =~ "fs-1130mfp"     ||
          model =~ "fs-2025d"       ||
          model =~ "km-2820") {

    ky_printer["req_type"] = "POST";
    ky_printer["login_url"] = "/start/login.cgi";
    ky_printer["login_data"] = "okhtmfile=%2Fopt1%2Findex.htm&failhtmfile=%2Fstart%2FStartAccessDenied.htm&func=authLogin&arg01_UserName=%%%USERNAME%%%&arg02_Password=%%%PASSWORD%%%&arg03_LoginType=&submit001=OK&arg01_UserName=&language=..%2Fopt1%2Findex.htm";
    ky_printer["http_status"] = "HTTP/1\.[01] 200";
    ky_printer["login_success"] = "[Ss]et-[Cc]ookie\s*:\s*level=3";

    return ky_printer;
  }

  else if(model =~ "taskalfa_4500i"  ||
          model =~ "taskalfa_2550ci" ||
          model =~ "taskalfa_3500i"  ||
          model =~ "taskalfa_4550ci" ||
          model =~ "taskalfa_5500i"  ||
          model =~ "fs-4300dn"       ||
          model =~ "fs-6525mfp"      ||
          model =~ "taskalfa_3050ci") {

    ky_printer["req_type"] = "POST";
    ky_printer["login_url"] = "/startwlm/login.cgi";
    ky_printer["login_data"] = "failhtmfile=%2Fstartwlm%2FStart_Wlm.htm&okhtmfile=%2Fstartwlm%2FStart_Wlm.htm&func=authLogin&arg03_LoginType=_mode_off&arg04_LoginFrom=_wlm_login&language=..%2Fwlmeng%2Findex.htm&hiddRefreshDevice=..%2Fstartwlm%2FHme_DvcSts.htm&hiddRefreshPanelUsed=..%2Fstartwlm%2FHme_PnlUsg.htm&hiddRefreshPaperid=..%2Fstartwlm%2FHme_Paper.htm&hiddRefreshTonerid=..%2Fstartwlm%2FHme_StplPnch.htm&hiddRefreshStapleid=..%2Fstartwlm%2FHme_Toner.htm&hiddnBackNavIndx=1&hiddRefreshDeviceBack=&hiddRefreshPanelUsedBack=&hiddRefreshPaperidBack=&hiddRefreshToneridBack=&hiddRefreshStapleidBack=&hiddCompatibility=&hiddPasswordToOpenChk=&hiddPasswordToOpen=&hiddRePasswordToOpen=&hiddPasswordToEditChk=&hiddPasswordToEdit=&hiddRePasswordToEdit=&hiddPrinting=&hiddChanges=&hiddCopyingOfText=&hiddEmaiSID=&hiddEmaiName=&hiddECM=&hiddDocID=&privid=&publicid=&attrtype=&attrname=&hiddFaxType=&hiddSMBNumber1=&hiddSMBNumber2=&hiddSMBNumber3=&hiddSMBNumber4=&hiddSMBNumber5=&hiddSMBNumber6=&hiddSMBNumber7=&hiddFTPNumber1=&hiddFTPNumber2=&hiddFTPNumber3=&hiddFTPNumber4=&hiddFTPNumber5=&hiddFTPNumber6=&hiddFTPNumber7=&hiddFAXAddress1=&hiddFAXAddress2=&hiddFAXAddress3=&hiddFAXAddress4=&hiddFAXAddress5=&hiddFAXAddress6=&hiddFAXAddress7=&hiddFAXAddress8=&hiddFAXAddress9=&hiddFAXAddress10=&hiddIFaxAdd=&hiddIFaxConnMode=&hiddIFaxResolution=&hiddIFaxComplession=&hiddIFaxPaperSize=&hiddImage=&hiddTest=&hiddDoc_Num=&hiddCopy=&hiddDocument=&hiddDocRec=&AddressNumberPersonal=&AddressNumberGroup=&hiddPersonAddressID=&hiddGroupAddressID=&hiddPrnBasic=&hiddPageName=&hiddDwnLoadType=&hiddPrintType=&hiddSend1=&hiddSend2=&hiddSend3=&hiddSend4=&hiddSend5=&hiddAddrBokBackUrl=&hiddAddrBokName=&hiddAddrBokFname=&hiddSendFileName=&hiddenAddressbook=&hiddenAddressbook1=&hiddSendDoc_Num=&hiddSendColor=&hiddSendAddInfo=&hiddSendFileFormat=&hiddRefreshDevice=..%2Fstartwlm%2FHme_DvcSts.htm&hiddRefreshPanelUsed=..%2Fstartwlm%2FHme_PnlUsg.htm&hiddRefreshPaperid=..%2Fstartwlm%2FHme_Paper.htm&hiddRefreshTonerid=..%2Fstartwlm%2FHme_StplPnch.htm&hiddRefreshStapleid=..%2Fstartwlm%2FHme_Toner.htm&hiddnBackNavIndx=0&hiddRefreshDeviceBack=&hiddRefreshPanelUsedBack=&hiddRefreshPaperidBack=&hiddRefreshToneridBack=&hiddRefreshStapleidBack=&hiddValue=&arg01_UserName=%%%USERNAME%%%&arg02_Password=%%%PASSWORD%%%&arg03_LoginType=&arg05_AccountId=&Login=Login&arg06_DomainName=&hndHeight=0";
    ky_printer["http_status"] = "HTTP/1\.[01] 200";
    ky_printer["login_success"] = "[Ss]et-[Cc]ookie\s*:\s*level=1";

    return ky_printer;
  }

  else if(model =~ "taskalfa_250ci") {

    ky_printer["req_type"] = "POST";
    ky_printer["login_url"] = "/start/login.cgi";
    ky_printer["login_data"] = "okhtmfile=%2Feng%2Findex.htm&failhtmfile=%2Fstart%2FStartAccessDenied.htm&func=authLogin&arg01_UserName=%%%USERNAME%%%&arg02_Password=%%%PASSWORD%%%&arg03_LoginType=&submit001=OK&arg01_UserName=&language=..%2Feng%2Findex.htm";
    ky_printer["http_status"] = "HTTP/1\.[01] 200";
    ky_printer["login_success"] = "[Ss]et-[Cc]ookie\s*:\s*level=3";

    return ky_printer;
  }

  set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#kyocera_get_login_details(): Unknown/not supported printer model '" + model + "' passed.");

  return;
}

function kyocera_error_exit(buf) {

  local_var buf;

  if(!buf || ereg(pattern:"HTTP/1\.[01] (404|500)", string:buf))
    exit(0);

  return TRUE;
}
