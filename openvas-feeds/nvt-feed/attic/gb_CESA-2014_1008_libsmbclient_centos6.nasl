# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.881980");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2014-08-06 12:06:21 +0200 (Wed, 06 Aug 2014)");
  script_cve_id("CVE-2014-3560");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for libsmbclient CESA-2014:1008 centos6");

  script_tag(name:"affected", value:"libsmbclient on CentOS 6");
  script_tag(name:"insight", value:"Samba is an open-source implementation of the Server Message
Block (SMB) or Common Internet File System (CIFS) protocol, which allows
PC-compatible machines to share files, printers, and other information.

A heap-based buffer overflow flaw was found in Samba's NetBIOS message
block daemon (nmbd). An attacker on the local network could use this flaw
to send specially crafted packets that, when processed by nmbd, could
possibly lead to arbitrary code execution with root privileges.
(CVE-2014-3560)

This update also fixes the following bug:

  * Prior to this update, Samba incorrectly used the O_TRUNC flag when using
the open(2) system call to access the contents of a file that was already
opened by a different process, causing the file's previous contents to be
removed. With this update, the O_TRUNC flag is no longer used in the above
scenario, and file corruption no longer occurs. (BZ#1115490)

All Samba users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing this
update, the smb service will be restarted automatically.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"CESA", value:"2014:1008");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-August/020466.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libsmbclient'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("CentOS Local Security Checks");

  # Initial advisory had a wrong subject so this was wrongly assigned to CentOS6 where only CentOS7 is vulnerable.
  # See: https://lists.centos.org/pipermail/centos-announce/2014-August/020467.html
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
