# SPDX-FileCopyrightText: 2009 E-Soft Inc.
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.66427");
  script_version("2025-01-13T08:32:03+0000");
  script_tag(name:"last_modification", value:"2025-01-13 08:32:03 +0000 (Mon, 13 Jan 2025)");
  script_tag(name:"creation_date", value:"2009-12-10 00:23:54 +0100 (Thu, 10 Dec 2009)");
  script_cve_id("CVE-2009-4023", "CVE-2009-4111");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Fedora Core 11 FEDORA-2009-12348 (php-pear-Mail)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 E-Soft Inc.");
  script_family("Fedora Local Security Checks");
  script_tag(name:"insight", value:"Update Information:

Fix CVE-2009-4023, CVE-2009-4111    PEAR's Mail class did not properly escape
content of mail header fields, when using the sendmail backend. A remote
attacker could send an email message, with specially-crafted headers to local
user, leading to disclosure of content and potentially, to modification of
arbitrary system file, once the email message was processed by the PEAR's Mail
class.

ChangeLog:

  * Fri Nov 27 2009 Remi Collet  1.1.14-5

  - Fix CVE-2009-4023 (#540842)

  - rename Mail.xml to php-pear-Mail.xml

  * Sun Jul 26 2009 Fedora Release Engineering  - 1.1.14-4");
  script_tag(name:"solution", value:"Apply the appropriate updates.

This update can be installed with the yum update program.  Use
su -c 'yum update php-pear-Mail' at the command line.");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=FEDORA-2009-12348");
  script_tag(name:"summary", value:"The remote host is missing an update to php-pear-Mail
announced via advisory FEDORA-2009-12348.
Note: This VT has been deprecated and is therefore no longer functional.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=540842");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
