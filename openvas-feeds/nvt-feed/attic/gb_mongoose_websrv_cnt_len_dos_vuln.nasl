# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900268");
  script_version("2025-03-06T05:38:27+0000");
  script_tag(name:"last_modification", value:"2025-03-06 05:38:27 +0000 (Thu, 06 Mar 2025)");
  script_tag(name:"creation_date", value:"2010-12-31 07:04:16 +0100 (Fri, 31 Dec 2010)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Mongoose Web Server Content-Length DoS Vulnerability");

  script_category(ACT_DENIAL);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Denial of Service");

  script_tag(name:"summary", value:"Mongoose Web Server is prone to denial of service (DoS)
  vulnerability.

  This VT has been deprecated as a duplicate of the VT 'Mongoose Web Server 'Content-Length' HTTP
  Header Remote DoS Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.103004).");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks if the host is
  still alive.");

  script_tag(name:"insight", value:"The flaw is due to the way Mongoose Web Server handles request
  with a big nagitive 'Content-Length' causing application crash.");

  script_tag(name:"impact", value:"Successful exploitation will let the remote unauthenticated
  attackers to cause a denial of service or possibly execute arbitrary code.");

  script_tag(name:"affected", value:"Mongoose Web Server version 2.11 and prior.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.");

  script_xref(name:"URL", value:"http://www.johnleitch.net/Vulnerabilities/Mongoose.2.11.Denial.Of.Service/74");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45602");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
