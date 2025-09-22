# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.115017");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-04-29 12:59:58 +0000 (Wed, 29 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:S/C:N/I:N/A:N");
  script_tag(name:"qod", value:"97");

  script_name("Linux: Mount data file partitions, CD/DVD, and USB partitions in noexec mode");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Policy");
  script_dependencies("compliance_tests.nasl");
  script_mandatory_keys("Compliance/Launch");

  script_xref(name:"URL", value:"https://support.huawei.com/enterprise/en/doc/EDOC1100098622");
  script_tag(name:"summary", value:"Mounting data file partitions in noexec mode can make all files
in the partitions nonexecutable, thus preventing security risks.");

  exit(0);
}

include("policy_functions.inc");

title = "Mount Data File Partitions, CD/DVD, and USB partitions in noexec mode.";
cmd = "None";
solution = "Mount data file partitions, CD/DVD, and USB partitions in noexec mode.";
test_type = "Manual Check";
default = "None";
value = "None";
compliant = "Yes";
comment = "No automatic test possible. Run 'mount' and check if all removable data partitions are mounted in noexec mode.";

policy_reporting(result:value, default:default, compliant:compliant, fixtext:solution,
  type:test_type, test:cmd, info:comment);

exit(0);