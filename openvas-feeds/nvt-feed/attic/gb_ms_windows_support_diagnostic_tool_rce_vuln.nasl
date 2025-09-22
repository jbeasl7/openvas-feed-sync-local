# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821253");
  script_version("2025-01-17T15:39:18+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2022-30190");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-01-17 15:39:18 +0000 (Fri, 17 Jan 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-02 14:00:00 +0000 (Thu, 02 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-01 11:37:17 +0530 (Wed, 01 Jun 2022)");
  script_name("Microsoft Windows Support Diagnostic Tool (MSDT) RCE Vulnerability (Follina)");

  script_tag(name:"summary", value:"This host is missing a workaround for a critical security flaw
  in the Microsoft Windows Support Diagnostic Tool (MSDT) dubbed 'Follina'.

  This VT has been deprecated and replaced by various VTs which are checking for an applied patch instead.");

  script_tag(name:"vuldetect", value:"Checks if the required workaround is missing on the target
  host.");

  script_tag(name:"insight", value:"The flaw exists due to the way MSDT is called using the URL
  protocol from certain applications such as Word from Microsoft Office.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to run arbitrary
  code with the privileges of the calling application. The attacker can then install programs, view,
  change, or delete data, or create new accounts in the context allowed by the user's rights.");

  script_tag(name:"affected", value:"- Microsoft Windows Server 2019

  - Microsoft Windows Server 2016

  - Microsoft Windows 7 x32/x64

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2008 x32

  - Microsoft Windows Server 2008 R2 x64

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2012 R2

  - Microsoft Windows 11

  - Microsoft Windows Server 2022

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1809/1607/21H1/20H2/21H2 x32/x64");

  script_tag(name:"solution", value:"The vendor has published a workaround. Please see the
  references for more information.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2022-30190");
  script_xref(name:"URL", value:"https://msrc-blog.microsoft.com/2022/05/30/guidance-for-cve-2022-30190-microsoft-support-diagnostic-tool-vulnerability/");
  script_xref(name:"URL", value:"https://doublepulsar.com/follina-a-microsoft-office-code-execution-vulnerability-1a47fce5629e");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
