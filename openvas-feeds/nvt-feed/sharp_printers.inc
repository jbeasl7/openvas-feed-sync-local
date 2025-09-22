# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

# IMPORTANT:
# For HTTP status code response checks like e.g. "HTTP/1\.[01] 200" don't include a "^" in front as
# such devices are known to not follow RFCs strictly or could show otherwise weird responses.

global_var sharp_cookie, sharp_last_user, sharp_last_pass;

# @brief Returns an array containing the URL for a Sharp printer detection
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
function get_sharp_detect_urls() {

  local_var sharp_detect_urls;

  sharp_detect_urls = make_array();

  sharp_detect_urls["/"]                      = "<title>(MX-M260N|AR-M155|AR-M450U|AR-M550U|MX-M700N|MX-M620N|AR-M351U|AR-M451U|MX-M550N|AR-M700U|AR-M276|MX-M310N|AR-168D|AR-M236|MX-M450U|AR-M237|MX-M350N|MX-M550U|AR-M160|AL-2051|AL-2061|MX-B201D)</title>";
  sharp_detect_urls["/login.html?/main.html"] = "<title>.* - ([^<]+)</title>";
  sharp_detect_urls["/link.html"]             = ">(AR-M350|im3511|im4512)<";

  return sharp_detect_urls;
}

function sharp_default_logins() {
  return make_list("admin:Sharp", "admin:1234", "Administrator:admin", "administrator:admin", "admin:admin", "admin:00000");
}

function check_sharp_default_login( model, port ) {

  # nb: sharp_cookie, sharp_last_user and sharp_last_pass are global vars
  local_var model, port;
  local_var sharp, logins, host, useragent, _login, user_pass, username, password, login_data, len;
  local_var req, buf, userpass, userpass64, c_buf;

  sharp = sharp_login_details(model:model, port:port);
  if(!sharp)
    return FALSE;

  logins = sharp_default_logins();

  host = http_host_name(port:port);
  useragent = http_get_user_agent();

  foreach _login(logins) {

    user_pass = split(_login, sep:":", keep:FALSE);
    username = user_pass[0];
    password = user_pass[1];

    login_data = sharp["login_data"];
    if(login_data) {
      login_data = str_replace(string:login_data, find:"%%%USERNAME%%%", replace:username);
      login_data = str_replace(string:login_data, find:"%%%PASSWORD%%%", replace:password);
    }

    len = strlen(login_data);

    if(sharp["req_type"] == "POST") {

      if(sharp["login_url_success"]) {
        req = string(sharp["req_type_success"], " ", sharp["login_url_success"], " HTTP/1.1\r\n",
                     "Host: ", host, "\r\n",
                     "User-Agent: ", useragent, "\r\n\r\n");

        buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
        sharp_error_exit(buf:buf);

        if(eregmatch(pattern:sharp["login_success"], string:buf)) {
          return 2; # setup without auth
        }
      }

      req = string("POST " , sharp["login_url"], " HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "User-Agent: ", useragent, "\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ", len, "\r\n");

      if(sharp_cookie)
        req +=  string("Cookie: ", sharp_cookie, "\r\n");

      req += string("\r\n", login_data, "\r\n");
    }

    else if(sharp["req_type"] == "GET") {

      if(sharp["req_auth"] == "BASIC") {

        userpass = username + ":" + password;
        userpass64 = base64(str:userpass);

        req = string("GET ", sharp["login_url"], " HTTP/1.1\r\n",
                     "Host: ", host, "\r\n");

        c_buf = http_send_recv(port:port, data:req + '\r\n', bodyonly:FALSE);
        sharp_error_exit(buf:c_buf);

        if(c_buf !~ "HTTP/1\.[01] 401" && c_buf !~ "HTTP/1\.[01] 302")
          return 2; # setup without auth

        req += string("Authorization: Basic ", userpass64, "\r\n\r\n");
      }
    } else {
      return FALSE;
    }

    buf = http_send_recv(port:port, data:req, bodyonly:FALSE); # login

    if(ereg(pattern:sharp["http_status"], string:buf)) {

      update_cookie(buf:buf);

      if(sharp["login_url_success"]) {

        req = string(sharp["req_type_success"], " ", sharp["login_url_success"], " HTTP/1.1\r\n",
                    "Host: ", host, "\r\n");

        if(sharp_cookie)
          req +=  string("Cookie: ", sharp_cookie, "\r\n");

        req += string("User-Agent: ", useragent, "\r\n\r\n");

        buf = http_send_recv(port:port, data:req, bodyonly:FALSE);
        sharp_error_exit(buf:buf);
      }

      if(eregmatch(pattern:sharp["login_success"], string:buf)) {
        sharp_last_user = username;
        sharp_last_pass = password;
        return 1;
      }
    }
  }
  return FALSE;
}

# @brief Returns an array with the details about the login/restricted pages to check authentication for depending
#        on the model provided
#
# @param model The model to return the details for
#
# @param port  The HTTP port of the remote system
#
# @note The "http_status" and "login_success" entries below are used in ereg() or eregmatch() calls
#       and thus special regex chars like a dot needs to be escaped. Also see the important note on
#       the top of this include.
#
# @return An array containing the needed information for authentication checks
#
#         ret_array["req_type"]          = the HTTP request type (GET/POST)
#         ret_array["login_url"]         = the URL to check authentication
#         ret_array["login_data"]        = the data to pass in the POST body for checking authentication (optional)
#         ret_array["req_type_success"]  = the HTTP request type to check if authentication was successful (optional)
#         ret_array["login_url_success"] = the URL to check if authentication was successful (optional)
#         ret_array["req_auth"]          = the kind of authentication (currently BASIC)
#         ret_array["http_status"]       = the HTTP status to expect from a successful authentication as a regex
#         ret_array["login_success"]     = regex to check for in case of successful authentication
#
function sharp_login_details( model, port ) {

  local_var model, port;
  local_var sharp;

  if(!model) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#model#-#sharp_login_details");
    return;
  }

  if(!port) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#sharp_login_details");
    return;
  }

  sharp = make_array();

  if(model =~ "MX-4100N"  ||
     model =~ "MX-M453U"  ||
     model =~ "MX-5001N"  ||
     model =~ "MX-2700FG" ||
     model =~ "MX-2310U"  ||
     model =~ "MX-2301N"  ||
     model =~ "MX-M453N"  ||
     model =~ "MX-6200N"  ||
     model =~ "MX-4111N"  ||
     model =~ "MX-M452N"  ||
     model =~ "MX-M362N"  ||
     model =~ "MX-2614N"  ||
     model =~ "MX-M453U"  ||
     model =~ "MX-M453N"  ||
     model =~ "MX-M453"   ||
     model =~ "MX-7001N"  ||
     model =~ "MX-2010U"  ||
     model =~ "MX-M363N"  ||
     model =~ "MX-M363U"  ||
     model =~ "MX-M363"   ||
     model =~ "MX-M363N"  ||
     model =~ "MX-3110N"  ||
     model =~ "MX-2600N"  ||
     model =~ "MX-4501N"  ||
     model =~ "MX-6240N"  ||
     model =~ "MX-M283N"  ||
     model =~ "MX-M354N"  ||
     model =~ "MX-C311"   ||
     model =~ "MX-M502N"  ||
     model =~ "MX-2300N"  ||
     model =~ "MX-M503N"  ||
     model =~ "MX-B402SC") {

    if(!sharp_cookie)
      sharp_set_cookie( url:"/main.html", port:port );

    sharp["req_type"] = "POST";
    sharp["login_url"] = "/login.html?/main.html";
    sharp["login_data"] = "ggt_select%2810009%29=3&ggt_textbox%2810003%29=%%%PASSWORD%%%&action=loginbtn&ggt_hidden%2810008%29=4";

    sharp["req_type_success"] = "GET";
    sharp["login_url_success"] = "/main.html";

    sharp["http_status"] = "HTTP/1\.[01] 302";
    sharp["login_success"] = "<!--Logoff \(L\)-->";

    return sharp;
  }

  else if(model =~ "MX-B201D" ||
          model =~ "AL-2051"  ||
          model =~ "AL-2061"  ||
          model =~ "AR-M160"  ||
          model =~ "AR-M236"  ||
          model =~ "MX-M450U" ||
          model =~ "AR-M237"  ||
          model =~ "MX-M620N" ||
          model =~ "MX-M350N" ||
          model =~ "MX-M550U" ||
          model =~ "MX-M310N" ||
          model =~ "MX-M700N" ||
          model =~ "AR-168D"  ||
          model =~ "AR-M700U" ||
          model =~ "MX-M550N" ||
          model =~ "AR-M451U" ||
          model =~ "AR-M351U" ||
          model =~ "AR-M550U" ||
          model =~ "AR-M450U" ||
          model =~ "AR-M155"  ||
          model =~ "MX-M260N" ||
          model =~ "AR-M350"  ||
          model =~ "im3511"   ||
          model =~ "im4512"   ||
          model =~ "AR-M276") {

    sharp["req_type"] = "GET";
    sharp["login_url"] = "/password.html";
    sharp["req_auth"] = "BASIC";

    sharp["http_status"] = "HTTP/1\.[01] 200";
    sharp["login_success"] = "<title>Password Setup Page";

    return sharp;
  }

  set_kb_item(name:"vt_debug_misc/" + get_script_oid(), value:get_script_oid() + "#-#sharp_login_details(): Unknown/not supported printer model '" + model + "' passed.");

  exit(0); # nb: We don't know this printer
}

function sharp_set_cookie(url, port) {

  local_var url, port;
  local_var req, buf, co;
  # nb: sharp_cookie is a global var

  req = http_get(item:url, port:port);
  buf = http_send_recv(port:port, data:req, bodyonly:FALSE);

  if(buf !~ "Set-Cookie\s*:.+")
    return FALSE;

  co = eregmatch(pattern:"[Ss]et-[Cc]ookie\s*:\s*([^; ]+)", string:buf);
  if(!isnull(co[1])) {
    sharp_cookie = co[1];
    return TRUE;
  }
  return FALSE;
}

function update_cookie(buf) {

  local_var buf;
  local_var co;
  # nb: sharp_cookie is a global var

  if(buf !~ "Set-Cookie\s*:.+")
    return FALSE;

  co = eregmatch(pattern:"[Ss]et-[Cc]ookie\s*:\s*([^; ]+)", string:buf);
  if(!isnull(co[1])) {
    sharp_cookie = co[1];
    return TRUE;
  }
  return FALSE;
}

function sharp_error_exit(buf) {

  local_var buf;

  if(!buf || ereg(pattern:"HTTP/1\.[01] (404|500)", string: buf))
    exit(0);

  return TRUE;
}
