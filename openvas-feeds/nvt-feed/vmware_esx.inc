# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

global_var sess, esxi_error, installed_bulletins, response, esxi_version;

esxi_error = NULL;
sess = NULL;
installed_bulletins = NULL;
response = NULL;
esxi_version = NULL;

# @brief Starts a session at the remote ESXi server by logging into the server
#        with the given credentials.
#
# @param port The port of the remote ESXi server.
# @param user The user to login into the remote ESXi server.
# @param pass The password to login into the remote ESXi server.
#
# @note The passed username and password will be XML escaped via @ref xml_escape to make sure no
#       reserved XML chars are passed to the created SOAP request which would make the XML invalid.
#
# @return TRUE if the login was possible/a session could be created, FALSE otherwise.
#
function start_esxi_session(port, user, pass) {

  local_var port, user, pass;
  local_var search, recv, sM, SessionManager, c;
  # nb: sess is a global_var on top

  if(!port)
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#start_esxi_session");

  if(!user)
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#user#-#start_esxi_session");

  if(!pass)
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pass#-#start_esxi_session");

  search = "VMware ESX";
  recv = _esxi_soap_request(data:'
                                <RetrieveServiceContent xmlns="urn:vim25">
                                  <_this type="ServiceInstance">ServiceInstance</_this>
                                </RetrieveServiceContent>',
                            search:search, port:port);

  if(!recv) {
    _esx_error(data:"ESXi 4.x/5.x/6.x/7.x/8.x: Initial connection failed.", search:search);
    return FALSE;
  }

  user = xml_escape(str:user);
  pass = xml_escape(str:pass);

  sM = eregmatch(pattern:'<sessionManager type="SessionManager">(.*)</sessionManager>', string:recv);
  if(!isnull(sM[1]))
    SessionManager = sM[1];
  else
    SessionManager = "ha-sessionmgr";

  search = "<key>";
  recv = _esxi_soap_request(data:'
                                <Login xmlns="urn:vim25">
                                  <_this type="SessionManager">' + SessionManager + '</_this>
                                  <userName>' + user + '</userName>
                                  <password>' + pass + '</password>
                                </Login>',
                            search:search, port:port);

  if(!recv) {
    _esx_error(data:"ESXi 4.x/5.x/6.x/7.x/8.x: Login failed.", search:search);
    return FALSE;
  }

  search = '[Ss]et-[Cc]ookie\\s*:\\s*vmware_soap_session="([^"]+)"';
  c = eregmatch(pattern:search, string:recv);

  if(isnull(c[1])) {
    _esx_error(data:"ESXi 4.x/5.x/6.x/7.x/8.x: Could not extract session cookie from response.", search:search);
    return FALSE;
  }

  sess = c[1];

  return TRUE;
}

# @brief Tries to gather/receive the installed bulletins/patches from the remote ESXi server for
#        ESXi versions 5.x, 6.x, 7.x and 8.x. For ESXi version 4.x @ref get_esxi4_x_vibs needs to
#        be used.
#        This function calls @ref parse_esxi_5_0_response internally which in addition saves
#        the installed bulletins/patches (if received successfully) into the internal KB.
#
# @param port The port of the remote ESXi server.
# @param user The user to login into the remote ESXi server.
# @param pass The password to login into the remote ESXi server.
#
# @return TRUE if it was possible installed bulletins/patches from the remote ESXi server
#         and FALSE in the case it wasn't possible or if the function was used for a wrong/
#         unsupported ESXi version.
#
function get_esxi5_0_vibs(port, user, pass) {

  local_var port, user, pass;
  local_var search, recv;
  # nb: esxi_version is a global_var on top.

  if(!port)
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_esxi5_0_vibs");

  if(!user)
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#user#-#get_esxi5_0_vibs");

  if(!pass)
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pass#-#get_esxi5_0_vibs");

  if(esxi_version !~ "^[5678]\.") {
    _esx_error(data:"ESXi 5.x/6.x/7.x/8.x: Wrong ESXi version. Expected: 5.x/6.x/7.x/8.x. Received: " + esxi_version, skip_search:TRUE, skip_response:TRUE);
    return FALSE;
  }

  if(!user || !pass) {
    _esx_error(data:"ESXi 5.x/6.x/7.x/8.x: username or password missing in internal knowledgebase.", skip_search:TRUE, skip_response:TRUE);
    return FALSE;
  }

  if(!start_esxi_session(port:port, user:user, pass:pass))
    return FALSE;

  search = "<VimEsxCLIsoftwareviblistResponse";
  recv = _esxi_soap_request(data:'
                            <VimEsxCLIsoftwareviblist xmlns="urn:vim25">
                              <_this type="VimEsxCLIsoftwarevib">ha-cli-handler-software-vib</_this>
                            </VimEsxCLIsoftwareviblist>',
                            search:search, port:port);

  if(!recv) {
    _esx_error(data:"ESXi 5.x/6.x/7.x/8.x: Failed to receive the installed bulletins/patches.", search:search);
    return FALSE;
  }

  if(parse_esxi_5_0_response(recv:recv))
    return TRUE;

  return FALSE;
}

# @brief Tries to gather/receive the installed bulletins/patches from the remote ESXi server for
#        ESXi version 4.x. For ESXi version 5.x, 6.x, 7.x or 8.x @ref get_esxi5_0_vibs needs to be used.
#        This function calls @ref parse_esxi_4_x_response internally which in addition saves
#        the installed bulletins/patches (if received successfully) into the internal KB.
#
# @param port The port of the remote ESXi server.
# @param user The user to login into the remote ESXi server.
# @param pass The password to login into the remote ESXi server.
#
# @return TRUE if it was possible installed bulletins/patches from the remote ESXi server
#         and FALSE in the case it wasn't possible or if the function was used for a wrong/
#         unsupported ESXi version.
#
function get_esxi4_x_vibs(port, user, pass) {

  local_var port, user, pass;
  local_var search, recv, hs, HostSystem, hpm, t, task, resp;
  # nb: esxi_version is a global_var on top.

  if(!port)
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_esxi4_x_vibs");

  if(!user)
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#user#-#get_esxi4_x_vibs");

  if(!pass)
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#pass#-#get_esxi4_x_vibs");

  if(esxi_version !~ "^4\.") {
    _esx_error(data:"ESXi 4.x: Wrong ESXi version. Expected: 4.x. Received: " + esxi_version, skip_search:TRUE, skip_response:TRUE);
    return FALSE;
  }

  if(!user || !pass) {
    _esx_error(data:"ESXi 4.x: username or password missing in internal knowledgebase.", skip_search:TRUE, skip_response:TRUE);
    return FALSE;
  }

  if(!start_esxi_session(port:port, user:user, pass:pass))
    return FALSE;

  search = "HostSystem";
  recv = _esxi_soap_request(data:'
                                <RetrieveProperties xmlns="urn:vim25">
                                <_this type="PropertyCollector">ha-property-collector</_this>
                                <specSet>
                                  <propSet>
                                    <type>HostSystem</type>
                                    <all>0</all>
                                  </propSet>
                                  <objectSet>
                                    <obj type="Folder">ha-folder-root</obj>
                                    <skip>0</skip>
                                    <selectSet xsi:type="TraversalSpec">
                                      <name>folderTraversalSpec</name>
                                      <type>Folder</type>
                                      <path>childEntity</path>
                                      <skip>0</skip>
                                    <selectSet>
                                      <name>folderTraversalSpec</name>
                                    </selectSet>
                                    <selectSet>
                                      <name>datacenterHostTraversalSpec</name>
                                    </selectSet>
                                    <selectSet>
                                      <name>datacenterVmTraversalSpec</name>
                                    </selectSet>
                                    <selectSet>
                                      <name>datacenterDatastoreTraversalSpec</name>
                                    </selectSet>
                                    <selectSet>
                                      <name>datacenterNetworkTraversalSpec</name>
                                    </selectSet>
                                    <selectSet>
                                      <name>computeResourceRpTraversalSpec</name>
                                    </selectSet>
                                    <selectSet>
                                      <name>computeResourceHostTraversalSpec</name>
                                    </selectSet>
                                    <selectSet>
                                      <name>hostVmTraversalSpec</name>
                                    </selectSet>
                                    <selectSet>
                                      <name>resourcePoolVmTraversalSpec</name>
                                    </selectSet>
                                    </selectSet>
                                    <selectSet xsi:type="TraversalSpec">
                                      <name>datacenterDatastoreTraversalSpec</name>
                                      <type>Datacenter</type>
                                      <path>datastoreFolder</path>
                                      <skip>0</skip>
                                    <selectSet>
                                      <name>folderTraversalSpec</name>
                                    </selectSet>
                                    </selectSet>
                                    <selectSet xsi:type="TraversalSpec">
                                      <name>datacenterNetworkTraversalSpec</name>
                                      <type>Datacenter</type>
                                      <path>networkFolder</path>
                                      <skip>0</skip>
                                    <selectSet>
                                      <name>folderTraversalSpec</name>
                                    </selectSet>
                                    </selectSet>
                                    <selectSet xsi:type="TraversalSpec">
                                      <name>datacenterVmTraversalSpec</name>
                                      <type>Datacenter</type>
                                      <path>vmFolder</path>
                                      <skip>0</skip>
                                    <selectSet>
                                      <name>folderTraversalSpec</name>
                                    </selectSet>
                                    </selectSet>
                                    <selectSet xsi:type="TraversalSpec">
                                      <name>datacenterHostTraversalSpec</name>
                                      <type>Datacenter</type>
                                      <path>hostFolder</path>
                                      <skip>0</skip>
                                    <selectSet>
                                      <name>folderTraversalSpec</name>
                                    </selectSet>
                                    </selectSet>
                                    <selectSet xsi:type="TraversalSpec">
                                      <name>computeResourceHostTraversalSpec</name>
                                      <type>ComputeResource</type>
                                      <path>host</path>
                                      <skip>0</skip>
                                    </selectSet>
                                    <selectSet xsi:type="TraversalSpec">
                                      <name>computeResourceRpTraversalSpec</name>
                                      <type>ComputeResource</type>
                                      <path>resourcePool</path>
                                      <skip>0</skip>
                                    <selectSet>
                                      <name>resourcePoolTraversalSpec</name>
                                    </selectSet>
                                    <selectSet>
                                      <name>resourcePoolVmTraversalSpec</name>
                                    </selectSet>
                                    </selectSet>
                                    <selectSet xsi:type="TraversalSpec">
                                      <name>resourcePoolTraversalSpec</name>
                                      <type>ResourcePool</type>
                                      <path>resourcePool</path>
                                      <skip>0</skip>
                                    <selectSet>
                                      <name>resourcePoolTraversalSpec</name>
                                    </selectSet>
                                    <selectSet>
                                      <name>resourcePoolVmTraversalSpec</name>
                                    </selectSet>
                                    </selectSet>
                                    <selectSet xsi:type="TraversalSpec">
                                      <name>hostVmTraversalSpec</name>
                                      <type>HostSystem</type>
                                      <path>vm</path>
                                      <skip>0</skip>
                                    <selectSet>
                                      <name>folderTraversalSpec</name>
                                    </selectSet>
                                    </selectSet>
                                    <selectSet xsi:type="TraversalSpec">
                                      <name>resourcePoolVmTraversalSpec</name>
                                      <type>ResourcePool</type>
                                      <path>vm</path>
                                      <skip>0</skip>
                                    </selectSet>
                                </objectSet>
                            </specSet>
                        </RetrieveProperties>',
                            search:search, port:port);

  if(!recv) {
    _esx_error(data:"ESXi 4.x: Preparing failed.", search:search);
    return FALSE;
  }

  hs = eregmatch(pattern:'<obj type="HostSystem">(.*)</obj>', string:recv);
  if(!isnull(hs[1])) {
    HostSystem = hs[1];
  } else {
    HostSystem = "ha-host";
  }

  search = "PatchManager";
  recv = _esxi_soap_request(data:'
                                <RetrieveProperties xmlns="urn:vim25">
                                <_this type="PropertyCollector">ha-property-collector</_this>
                                <specSet>
                                  <propSet>
                                    <type>HostSystem</type>
                                    <all>0</all>
                                    <pathSet>configManager.patchManager</pathSet>
                                  </propSet>
                                  <objectSet>
                                    <obj type="HostSystem">' + HostSystem + '</obj>
                                  </objectSet>
                                </specSet>
                                </RetrieveProperties>',
                            search:search, port:port);

  if(!recv) {
    _esx_error(data:"ESXi 4.x: Initiating PatchManager failed.", search:search);
    return FALSE;
  }

  search = '<val type="HostPatchManager" xsi:type="ManagedObjectReference">(.*)</val>';
  hpm = eregmatch(pattern:search, string:recv);
  if(!isnull(hpm[1])) {
    HostPatchManager = hpm[1];
  } else {
    _esx_error(data:"ESXi 4.x: PatchManager not found on this system.", search:search);
    return FALSE;
  }

  search = "Query-";
  recv = _esxi_soap_request(data:'
                                <QueryHostPatch_Task xmlns="urn:vim25">
                                  <_this type="HostPatchManager">' + HostPatchManager + '</_this>
                                </QueryHostPatch_Task>',
                            search:search, port:port);

  if(!recv) {
    _esx_error(data:"ESXi 4.x: Getting Task ID failed.", search:search);
    return FALSE;
  }

  search = '<returnval type="Task">(.*Query-[0-9]+)</returnval>';
  t = eregmatch(pattern:search, string:recv);
  if(isnull(t[1])) {
    _esx_error(data:"ESXi 4.x: Could not extract Task ID.", search:search);
    return FALSE;
  }

  task = t[1];

  recv = get_installed_esxi_4_x_bulletins(task:task, port:port);
  if(!recv) {
    _esx_error(data:"ESXi 4.x: Could not get installed bulletins/patches.", skip_search:TRUE, skip_response:TRUE);
    return FALSE;
  }

  if(parse_esxi_4_x_response(recv:recv))
    return TRUE;

  return FALSE;
}

# @brief Tries to gather/receive the installed bulletins/patches from the remote ESXi server for
#        a given / specific task. This function is an internal function not to be called directly.
#
# @param task The task (id?) which is used to gather/receive the required information.
# @param port The port of the remote ESXi server to collect the installed bulletins/patch from.
#
# @return The received response/data for the gathering request or FALSE if it wasn't possible
#         to connect to the remote server or unexpected data was received.
#
function get_installed_esxi_4_x_bulletins(task, port) {

  local_var task, port;
  local_var max_retries, i, recv, ec, ed;
  # nb: Response is a global_var on top

  if(!port)
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#get_installed_esxi_4_x_bulletins");

  if(isnull(task))
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#task#-#get_installed_esxi_4_x_bulletins");

  max_retries = 15;
  i = 0;

  while(TRUE) {

    i++;

    if(i > max_retries) {
      response = 'Failed to get the installed bulletins/patches after ' + max_retries + ' retries\nLast recv was: ' + recv + '\n';
      return FALSE;
    }

    recv = _esxi_soap_request(data:'
                <RetrieveProperties xmlns="urn:vim25">
                <_this type="PropertyCollector">ha-property-collector</_this>
                <specSet>
                  <propSet>
                    <type>Task</type>
                    <all>1</all>
                  </propSet>
                  <objectSet>
                    <obj type="Task">' + task +'</obj>
                  </objectSet>
                </specSet>
              </RetrieveProperties>', port:port);

    if(!recv) {
      return FALSE;
    }

    recv = str_replace(string:recv, find:"&gt;", replace:">");
    recv = str_replace(string:recv, find:"&lt;", replace:"<");
    recv = str_replace(string:recv, find:"&quot;", replace:'"');

    if('<state>error</state>' >< recv)
      return FALSE;

    if('<state>success</state>' >< recv) {

      if('<error' >< recv && '</error>' >< recv) { # even if we got a success on the _query_, the PatchManager could fail...

        ec = eregmatch(pattern:'<errorCode>([0-9]+)</errorCode>', string:recv);
        if(!isnull(ec[1]))
          response = 'Code: ' + ec[1] + '\n';

        ed = eregmatch(pattern:'<errorDesc>(.*)</errorDesc>', string:recv);
        if(!isnull(ed[1]))
          response += 'Message: ' + ed[1] + '\n\n';

        return FALSE;
      }
      return recv;
    }
    sleep(3);
  }
  return FALSE;
}

# @brief Parses the received data (internally passed by @ref get_esxi4_x_vibs) and saves the
#        collected information into the internal KB.
#
# @param recv The data to parse the response from.
#
# @return TRUE if the data was parsed successful (e.g. expected data included in the parsed data),
#         FALSE otherwise.
#
function parse_esxi_4_x_response(recv) {

  local_var recv;
  local_var bl, bulletins, last, _line, datematch, date, ib;
  # nb: esxi_version and installed_bulletins are global_vars on top.

  if(strlen(recv) < 1) {
    _esx_error(data:"ESXi 4.x: Unexpected response from ESXi server.", search:"Length > 0");
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#recv#-#parse_esxi_4_x_response");
    return FALSE;
  }

  bl = split(recv);

  recv = str_replace(string:recv, find:string("\n"), replace:"");
  recv = str_replace(string:recv, find:string("\r"), replace:"");
  recv = str_replace(string:recv, find:string("\t"), replace:"");
  recv = ereg_replace(string:recv, pattern:">[ ]+<", replace:"><");

  bulletins = eregmatch(pattern:"(<bulletin>.*</bulletin>)", string:recv);

  if(isnull(bulletins[1])) {
    set_kb_item(name:'VMware/ESXi/' + esxi_version + '/unpatched', value:TRUE);
    log_message(data:'Could not found a single bulletin installed on this host. Assuming this\nis a completely unpatched system. \nRECV:\n' + recv + '\n');
    return TRUE;
  }

  last = NULL;

  foreach _line(bl) {

    if("<releaseDate>" >< _line) {

      datematch = eregmatch(pattern:"(20[0-9][0-9]-[012][0-9]-[0-3][0-9])", string:_line);
      date = datematch[1];

      if(!isnull(date) && (isnull(last) || date > last))
        last = date;
    }

    if(ib = eregmatch(pattern:"<id>(ESXi?[0-9]+-.*)</id>", string:_line)) {
      if(!isnull(ib[1])) {
        installed_bulletins += ib[1] + '\n';
      }
    }
  }

  if(installed_bulletins) {
    set_kb_item(name:'VMware/esxi/' + esxi_version + '/bulletins', value:chomp(str_replace(string:installed_bulletins, find:'\n', replace:" ")));
  }

  if(!isnull(last)) {
    set_kb_item(name:'VMware/esxi/' + esxi_version + '/last_bulletin', value:last);
    return TRUE;
  } else {
    _esx_error(data:"ESXi 4.x: Could not extract date of last bulletin.", skip_search:TRUE, skip_response:TRUE);
    return FALSE;
  }
}

# @brief Parses the received data (internally passed by @ref get_esxi5_0_vibs) and saves the
#        collected information into the internal KB.
#
# @param recv The data to parse the response from.
#
# @return TRUE if the data was parsed successful (e.g. expected data included in the parsed data),
#         FALSE otherwise.
#
function parse_esxi_5_0_response(recv) {

  local_var recv;
  local_var bl, bulletins, _line, datematch, date, last, ib, ibs;
  # nb: esxi_version and installed_bulletins are global_vars on top.

  if(strlen(recv) < 1) {
    _esx_error(data:"ESXi 5.x/6.x/7.x/8.x: Unexpected response from ESXi server.", search:"Length > 0");
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#recv#-#parse_esxi_5_0_response");
    return FALSE;
  }

  bl = split(recv, sep:"><", keep:FALSE);

  bulletins = eregmatch(pattern:"(<returnval>.*</returnval>)", string:recv);

  recv = str_replace(string:recv, find:string("\n"), replace:"");
  recv = str_replace(string:recv, find:string("\r"), replace:"");
  recv = str_replace(string:recv, find:string("\t"), replace:"");
  recv = ereg_replace(string:recv, pattern:">[ ]+<", replace:"><");

  foreach _line(bl) {

    if("releasedate" >< tolower(_line) || "creationdate" >< tolower(_line)) {

      datematch = eregmatch(pattern:"(20[0-9][0-9]-[012][0-9]-[0-3][0-9])", string:_line);
      date = datematch[1];

      if(!isnull(date) && (isnull(last) || date > last))
        last = date;
    }

    if(ib = eregmatch(pattern:"ID>([^<]+)</ID", string:_line)) {
      if(!isnull(ib[1])) {
        installed_bulletins += ib[1] + '\n';
      }
    }
  }

  if(installed_bulletins) {
    ibs = chomp(str_replace(string:installed_bulletins, find:'\n', replace:" "));
    if(last) {
      installed_bulletins += '\n\nLast ReleaseDate: ' + last + '\n';
    }
    set_kb_item(name:"VMware/esxi/" + esxi_version + "/bulletins", value:ibs);
  }

  if(!isnull(last)) {
    set_kb_item(name:'VMware/esxi/' + esxi_version + '/last_bulletin', value:last);
    return TRUE;
  } else {
    _esx_error(data:"ESXi 5.x/6.x/7.x/8.x: Could not extract date of last bulletin.", skip_search:TRUE, skip_response:TRUE);
    return FALSE;
  }
}

# @brief Builds a SOAP header and footer around the passed data.
#
# @param data The data to include in the built SOAP request.
#
# @return The built SOAP request as a string.
#
function _esxi_build_soap(data) {

  local_var data;
  local_var soap_header, soap_footer;

  if(isnull(data))
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#data#-#_esxi_build_soap");

  soap_header = '<?xml version="1.0" encoding="UTF-8"?>
   <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
                     xmlns:xsd="http://www.w3.org/2001/XMLSchema"
                     xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
   <soapenv:Body>';

  soap_footer = '</soapenv:Body>
               </soapenv:Envelope>';

  return soap_header + data + soap_footer;
}

# @brief Sends a SOAP POST request with the given data to the '/sdk/webService' SOAP API
#        endpoint of an ESXi server and receives the response.
#
# @param port The port of the remote ESXi server to send the data to.
# @param data The SOAP data to send to the remote ESXi server.
# @param search The (optional) expected data which should be included in the response.
#               This search pattern is case sensitive and doesn't support regexes.
#
# @return The received data or FALSE if no connection could be established to the remote
#         ESXi server, the received data didn't matched the (optional) search text
#         given to the search parameter or any additional issue occurred during the connection.
#
function _esxi_soap_request(port, data, search) {

  local_var port, data, search;
  local_var soc, soap, len, host, req, buf, recv, fault, detail;
  # nb: sess and response are global_vars on top

  if(!port)
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#port#-#_esxi_soap_request");

  response = NULL;

  soc = open_sock_tcp(port);
  if(!soc) {
    _esx_error(data:"ESXi 4.x/5.x/6.x/7.x/8.x: Could not create socket.", skip_search:TRUE, skip_response:TRUE);
    return FALSE;
  }

  soap = _esxi_build_soap(data:data);

  len = strlen(soap);
  host = http_host_name(port:port);

  req = string("POST /sdk/webService HTTP/1.1\r\n",
               "Connection: Close\r\n",
               "User-Agent: VI Perl\r\n",
               "Host: ", host, "\r\n",
               "Content-Length: ", len, "\r\n",
               'SOAPAction: "urn:vim25/5.0"', "\r\n");

  if(strlen(sess)) {
    req += string('Cookie: vmware_soap_session="', sess, '"', "\r\n");
  }

  req += string("Content-Type: text/xml\r\n",
                "\r\n");

  req += soap;
  req += string("\r\n");

  send(socket:soc, data:req);

  while(buf = recv(socket:soc, length:1024))
    recv += buf;

  close(soc);

  # nb: At least against a ESXi 6.7 the while above doesn't receive the required data
  # but http_send_recv() works. Currently it's unclear why a while loop was used in the
  # past, it might be possible that older ESX(i) versions had problems with http_send_recv()
  # so try with http_send_recv() again.
  if(!recv) {
    recv = http_send_recv(port:port, data:req);
    if(!recv)
      return FALSE;
  }

  response = recv;

  if(recv !~ "^HTTP/1\.[01] 200") {

    if("<faultstring>" >< response) {

      fault = eregmatch(pattern:"<faultstring>(.*)</faultstring>", string:response);
      if(!isnull(fault[1])) {
        response = fault[1];
        detail = eregmatch(pattern:"<detail>(.*)</detail>", string:response);
        if(!isnull(detail[1])) {
          response += '\n\nDetail:\n' + detail[1] + '\n';
        }
        return FALSE;
      }
    }
    return FALSE;
  }

  if(search) {
    if(search >!< recv)
      return FALSE;
  }

  return recv;
}

# @brief Saves the given information in form of an error report in an internal global variable 'esxi_error'.
#
# @param data The text/data to be used to state the reason/info on the occurred error/problem.
# @param search The search text which was used by the calling function to verify e.g. a response of ESXi.
# @param skip_search If set to TRUE the reporting text about the expected content in the response is not included.
# @param skip_response If set to TRUE the reporting text about the received response is not included.
#
# @return NULL
#
function _esx_error(data, search, skip_search, skip_response) {

  local_var data, search, skip_search, skip_response;
  # nb: esxi_error and response are global_vars on top

  esxi_error = "The following problem(s) happened during the communication with the ESXi server:";
  esxi_error += '\n\nReason/Info:\n';

  if(data)
    esxi_error += data;
  else
    esxi_error += 'None received/given.';

  if(!skip_search) {
    esxi_error += '\n\nExpected content in response:\n';
    if(search)
      esxi_error += search;
    else
      esxi_error += 'None received/given';
  }

  if(!skip_response) {
    esxi_error += '\n\nReceived response:\n';
    if(response)
      esxi_error += response;
    else
      esxi_error += "No response received from ESXi server.";
  }
}

# @brief Checks if the remote ESXi server is missing a patch/update given within
#        the patch parameter.
#
# @param esxi_version The (required) ESXi version to check/for which this missing patch applies.
# @param patch The (required) ESXi patch which needs to be installed at the remove ESXi server so
#              that this function doesn't report a vulnerability. Example: VIB:esx-base:6.5.0-0.15.5224529
#
# @return TRUE if the remote ESXi server is missing the given patch. FALSE if not missing, the check doesn't
#         apply for the installed ESXi version, the ESXi server is unpatched or if the esxi_version or patch
#         parameter wasn't given.
#
function esxi_patch_missing(esxi_version, patch) {

  local_var esxi_version, patch;
  local_var esxi_kb_version, report, bulletins, last_bulletin, p, pa, pa_version;
  local_var _bulletin, installed, ip, iv, check_patch, pd, pdate, patch_date;

  if(!esxi_version) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#esxi_version#-#esxi_patch_missing");
    return FALSE;
  }

  if(!patch) {
    set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#patch#-#esxi_patch_missing");
    return FALSE;
  }

  esxi_kb_version = get_kb_item("VMware/ESX/version");
  if(!esxi_kb_version)
    return FALSE;

  if(esxi_version != esxi_kb_version)
    return FALSE;

  if(get_kb_item("VMware/ESXi/" + esxi_kb_version + "/unpatched")) {
    report =  "Found ESX(i) version:  " + esxi_kb_version + '\n';
    report += 'Missing ESX(i) patch:  Unpatched system\n';
    report += 'Date of last installed\nbulletin:              N/A';
    return report;
  }

  bulletins = get_kb_item("VMware/esxi/" + esxi_kb_version + "/bulletins");
  last_bulletin = get_kb_item("VMware/esxi/" + esxi_kb_version + "/last_bulletin");

  if("VIB:" >< patch) {

    p = split(patch, sep:":", keep:FALSE);

    if(isnull(p[1]) || isnull(p[2]))
      return FALSE;

    pa = p[1];
    pa_version = p[2];

    bulletins = split(bulletins, sep:" ", keep:FALSE);

    foreach _bulletin(bulletins) {

      if("_" + pa + "_" >< _bulletin) {

        installed = split(_bulletin, sep:"_", keep:FALSE);

        ip = installed[max_index(installed)-2];
        iv = installed[max_index(installed)-1];

        if(ip >!< pa)
          return FALSE;

        if(("vmw" >< pa_version && "vmw" >!< iv) || ("vmw" >< iv && "vmw" >!< pa_version))
          return FALSE;

        if("vmw" >< pa_version && "vmw" >< iv) {
          pa_version = str_replace(string:pa_version, find:"vmw", replace:"");
          iv = str_replace(string:iv, find:"vmw", replace:"");
        }

        if(version_is_less(version:iv, test_version:pa_version)) {
          report =  "Found ESX(i) version:  " + esxi_kb_version + '\n';
          report += "Missing ESX(i) patch:  " + patch + '\n';
          if(!last_bulletin)
            last_bulletin = "N/A";
          report += 'Date of last installed\nbulletin:              ' + last_bulletin;
          return report;
        }

        return FALSE;
      }
    }
  } else {

    if(bulletins) {

      if(patch =~ "-Update[0-9]+:") {
        check_patch = split(patch, sep:":", keep:FALSE);
        if(isnull(check_patch[0]))
          return FALSE;

        check_patch = check_patch[0];
      } else {
        check_patch = patch;
      }

      if(egrep(pattern:check_patch, string:bulletins)) {
        return FALSE;
      }
    }

    if(last_bulletin) {

      if(patch !~ "-Update[0-9]+") {
        pd = eregmatch(string:patch, pattern:"^ESXi?[0-9]+-(20[0-9][0-9])([0-9][0-9])[0-9]+-[A-Z]+$");

        if(isnull(pd[1]) || isnull(pd[2]))
          return FALSE;

        pdate = pd[1] + "-" + pd[2] + "-01";
      }

      if(patch =~ "-Update[0-9]+:") {
        patch_date = split(patch, sep:":", keep:FALSE);
        if(isnull(patch_date[1]))
          return FALSE;

        pdate = patch_date[1];
      }

      if(pdate <= last_bulletin)
        return FALSE;
    }
  }

  report =  "Found ESX(i) version:  " + esxi_kb_version + '\n';
  report += "Missing ESX(i) patch:  " + patch + '\n';
  if(!last_bulletin)
    last_bulletin = "N/A";
  report += 'Date of last installed\nbulletin:              ' + last_bulletin;
  return report;
}

# @brief Builds a "remote detection" report from the given information.
#
# @param ver The (required) installed version of the remote server (e.g. 6.7.0) to include in the report.
# @param build The (required) currently installed build of the remote server.
# @param fixed_build The (required) build including the fix.
# @param typ The (optional) type of the remote server (e.g. ESXi, vCenter) to include in the report.
#            Defaults to 'ESXi' if not given.
#
# @return A string including a report with the given information or NULL if one of the required parameters is missing.
#
function esxi_remote_report(ver, build, fixed_build, typ) {

  local_var ver, build, fixed_build, typ;
  local_var space, report;

  if(!ver || !build || !fixed_build) {

    if(!ver)
      set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#ver#-#esxi_remote_report");

    if(!build)
      set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#build#-#esxi_remote_report");

    if(!fixed_build)
      set_kb_item(name:"vt_debug_empty/" + get_script_oid(), value:get_script_oid() + "#-#fixed_build#-#esxi_remote_report");

    return;
  }

  space = ' ';
  if(!typ) {
    typ = 'ESXi';
    space = '    ';
  }

  report = typ + ' Version:' + space + ver + '\n' +
           'Detected Build:  ' + build + '\n' +
           'Fixed Build:     ' + fixed_build + '\n';

  return report;
}
