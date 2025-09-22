# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_xref(name:"URL", value:"http://lists.mandriva.com/security-announce/2011-01/msg00005.php");
  script_oid("1.3.6.1.4.1.25623.1.0.831305");
  script_version("2023-07-14T16:09:26+0000");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:26 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-14 16:07:43 +0100 (Fri, 14 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_xref(name:"MDVSA", value:"2011:004");
  script_cve_id("CVE-2010-2094");
  script_name("Mandriva Update for php-phar MDVSA-2011:004 (php-phar)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-phar'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Mandrake Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mandriva_mandrake_linux", "ssh/login/release", re:"ssh/login/release=MNDK_mes5");
  script_tag(name:"affected", value:"php-phar on Mandriva Enterprise Server 5,
  Mandriva Enterprise Server 5/X86_64");
  script_tag(name:"insight", value:"A vulnerability has been found and corrected in php-phar:

  Multiple format string vulnerabilities in the phar extension in PHP
  5.3 before 5.3.2 allow context-dependent attackers to obtain sensitive
  information (memory contents) and possibly execute arbitrary code
  via a crafted phar:// URI that is not properly handled by the (1)
  phar_stream_flush, (2) phar_wrapper_unlink, (3) phar_parse_url, or
  (4) phar_wrapper_open_url functions in ext/phar/stream.c, and the (5)
  phar_wrapper_open_dir function in ext/phar/dirstream.c, which triggers
  errors in the php_stream_wrapper_log_error function (CVE-2010-2094).

  The updated packages have been upgraded to the latest version (2.0.0)
  and patched to correct this issue.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "MNDK_mes5")
{

  if ((res = isrpmvuln(pkg:"php-phar", rpm:"php-phar~2.0.0~0.1mdvmes5.1", rls:"MNDK_mes5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
