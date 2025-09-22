# SPDX-FileCopyrightText: 2005 Nate Haggard (SecurityMetrics inc.)
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10922");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("/CVS/Entries accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Nate Haggard (SecurityMetrics inc.)");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"Your website allows read access to the CVS/Entries file.

  This VT has been deprecated and the check was merged into the following VT:

  Source Control Management (SCM) Files Accessible (OID: 1.3.6.1.4.1.25623.1.0.111084).");

  script_tag(name:"impact", value:"This exposes all file names in your CVS module on your website.");

  script_tag(name:"solution", value:"Change your website permissions to deny access to your CVS directory.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
