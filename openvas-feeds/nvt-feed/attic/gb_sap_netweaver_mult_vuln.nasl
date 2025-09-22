# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106082");
  script_version("2024-04-04T05:05:25+0000");
  script_tag(name:"last_modification", value:"2024-04-04 05:05:25 +0000 (Thu, 04 Apr 2024)");
  script_tag(name:"creation_date", value:"2016-05-23 09:47:56 +0700 (Mon, 23 May 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2012-1289", "CVE-2012-1290", "CVE-2012-1291", "CVE-2012-1292");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SAP NetWeaver Multiple Vulnerabilities (1585527, 1583300, 1585527)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"SAP NetWeaver is prone to multiple vulnerabilities.

  This VT has been deprecated because it is covering a currently unsupported product. It is
  therefore no longer functional.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SAP NetWeaver contains multiple vulnerabilities:

  - CVE-2012-1289: Multiple directory traversal vulnerabilities in SAP NetWeaver 7.0 allow remote
  authenticated users to read arbitrary files via a .. (dot dot) in the logfilename parameter to
  b2b/admin/log.jsp, b2b/admin/log_view.jsp in the Internet Sales (crm.b2b) component, or
  ipc/admin/log.jsp or ipc/admin/log_view.jsp in the Application Administration
  (com.sap.ipc.webapp.ipc) component.

  - CVE-2012-1290: Cross-site scripting (XSS) vulnerability in b2b/auction/container.jsp in the
  Internet Sales (crm.b2b) module in SAP NetWeaver 7.0 allows remote attackers to inject arbitrary
  web script or HTML via the _loadPage parameter.

  - CVE-2012-1291: Unspecified vulnerability in the com.sap.aii.mdt.amt.web.AMTPageProcessor servlet
  in SAP NetWeaver 7.0 allows remote attackers to obtain sensitive information about the Adapter
  Monitor via unspecified vectors, possibly related to the EnableInvokerServletGlobally property in
  the servlet_jsp service.

  - CVE-2012-1292: Unspecified vulnerability in the MessagingSystem servlet in SAP NetWeaver 7.0
  allows remote attackers to obtain sensitive information about the MessagingSystem Performance Data
  via unspecified vectors.");

  script_tag(name:"impact", value:"A remote attacker may obtain sensitive information or read
  arbitrary files.");

  script_tag(name:"affected", value:"SAP NetWeaver version 7.0.");

  script_tag(name:"solution", value:"See the referenced vendor advisories for a solution.");

  script_xref(name:"URL", value:"https://launchpad.support.sap.com/#/notes/1585527");
  script_xref(name:"URL", value:"https://launchpad.support.sap.com/#/notes/1583300");
  script_xref(name:"URL", value:"https://launchpad.support.sap.com/#/notes/1585527");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);