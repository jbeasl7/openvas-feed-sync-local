# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805066");
  script_version("2023-08-25T16:09:51+0000");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-08-25 16:09:51 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2015-04-22 12:59:34 +0530 (Wed, 22 Apr 2015)");
  script_tag(name:"qod_type", value:"remote_vul");
  script_name("Apache Spark Cluster Arbitrary Code Execution Vulnerability");

  script_tag(name:"summary", value:"This VT has been deprecated and is therefore no longer
  functional.

  Apache Spark Cluster is prone to an arbitrary code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted request via HTTP GET and
  check whether it is able to read the secured data or not.");

  script_tag(name:"insight", value:"Apache Spark contains a flaw that is
  triggered when submitting a specially crafted job to an unsecured
  cluster.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to execute arbitrary code.");

  script_tag(name:"affected", value:"Apache Spark Cluster versions 0.0.x, 1.1.x, 1.2.x, 1.3.x");

  script_tag(name:"solution", value:"No known solution was made available
  for at least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/36562");
  script_xref(name:"URL", value:"http://codebreach.in/blog/2015/03/arbitary-code-execution-in-unsecured-apache-spark-cluster");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Web application abuses");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
