# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802682");
  script_version("2023-06-27T05:05:30+0000");
  script_cve_id("CVE-2012-5568");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2012-12-05 12:17:34 +0530 (Wed, 05 Dec 2012)");
  script_name("Apache Tomcat Partial HTTP Requests DoS Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("Web Servers");

  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=880011");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56686");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2012/11/26/2");
  script_xref(name:"URL", value:"http://captainholly.wordpress.com/2009/06/19/slowloris-vs-tomcat/");
  script_xref(name:"URL", value:"http://tomcat.10.n6.nabble.com/How-does-Tomcat-handle-a-slow-HTTP-DoS-tc2147776.html");
  script_xref(name:"URL", value:"http://tomcat.10.n6.nabble.com/How-does-Tomcat-handle-a-slow-HTTP-DoS-tc2147779.html");
  script_xref(name:"URL", value:"https://tomcat.apache.org/security-7.html#Not_a_vulnerability_in_Tomcat");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause
  a denial of service conditions.");

  script_tag(name:"affected", value:"Apache Tomcat version 7.0.x.");

  script_tag(name:"insight", value:"The flaw is caused by configuring an appropriate timeout using
  the connectionTimeout property for the relevant Connector(s) defined in server.xml.");

  script_tag(name:"summary", value:"Apache Tomcat Server is prone to a denial of service (DoS) vulnerability.

  This VT has been deprecated for the reasons explained by the Apache Tomcat team in the references.");

  script_tag(name:"solution", value:"Update to Apache Tomcat 7.0.52 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);