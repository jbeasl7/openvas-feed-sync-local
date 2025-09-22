# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.882514");
  script_version("2023-07-12T05:05:04+0000");
  script_tag(name:"last_modification", value:"2023-07-12 05:05:04 +0000 (Wed, 12 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-06-24 05:27:04 +0200 (Fri, 24 Jun 2016)");
  script_cve_id("CVE-2015-8869");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for ocaml CESA-2016:1296 centos7");
  script_tag(name:"summary", value:"Check the version of ocaml");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"OCaml is a high-level, strongly-typed,
functional, and object-oriented programming language from the ML family of
languages. The ocaml packages contain two batch compilers
(a fast bytecode compiler and an optimizing native-code compiler), an
interactive top level system, parsing tools (Lex, Yacc, Camlp4), a replay
debugger, a documentation generator, and a comprehensive library.

Security Fix(es):

  * OCaml versions 4.02.3 and earlier have a runtime bug that, on 64-bit
platforms, causes size arguments to internal memmove calls to be
sign-extended from 32- to 64-bits before being passed to the memmove
function. This leads to arguments between 2GiB and 4GiB being interpreted
as larger than they are (specifically, a bit below 2^64), causing a
buffer overflow. Further, arguments between 4GiB and 6GiB are interpreted
as 4GiB smaller than they should be, causing a possible information
leak. (CVE-2015-8869)");
  script_tag(name:"affected", value:"ocaml on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"CESA", value:"2016:1296");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2016-June/021933.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"ocaml", rpm:"ocaml~4.01.0~22.7.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ocaml-camlp4", rpm:"ocaml-camlp4~4.01.0~22.7.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ocaml-camlp4-devel", rpm:"ocaml-camlp4-devel~4.01.0~22.7.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ocaml-compiler-libs", rpm:"ocaml-compiler-libs~4.01.0~22.7.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ocaml-docs", rpm:"ocaml-docs~4.01.0~22.7.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ocaml-emacs", rpm:"ocaml-emacs~4.01.0~22.7.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ocaml-labltk", rpm:"ocaml-labltk~4.01.0~22.7.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ocaml-labltk-devel", rpm:"ocaml-labltk-devel~4.01.0~22.7.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ocaml-ocamldoc", rpm:"ocaml-ocamldoc~4.01.0~22.7.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ocaml-runtime", rpm:"ocaml-runtime~4.01.0~22.7.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ocaml-source", rpm:"ocaml-source~4.01.0~22.7.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ocaml-x11", rpm:"ocaml-x11~4.01.0~22.7.el7_2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
