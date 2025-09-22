# SPDX-FileCopyrightText: 2016 SCHUTZWERK GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111084");
  script_version("2023-08-01T13:29:10+0000");
  script_tag(name:"last_modification", value:"2023-08-01 13:29:10 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"creation_date", value:"2016-02-04 09:00:00 +0100 (Thu, 04 Feb 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Source Control Management (SCM) Files/Folders Accessible (HTTP)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script attempts to identify files/folders of a SCM
  accessible at the webserver.");

  script_tag(name:"vuldetect", value:"Check the response if SCM files/folders are accessible.");

  script_tag(name:"insight", value:"Currently the script is checking for files/folders of the
  following SCM software:

  - Git (.git)

  - Mercurial (.hg)

  - Bazaar (.bzr)

  - CVS (CVS/Root, CVS/Entries)

  - Subversion (.svn)");

  script_tag(name:"impact", value:"Based on the information provided in these files/folders an
  attacker might be able to gather additional info about the structure of the system and its
  applications.");

  script_tag(name:"solution", value:"Restrict access to the SCM files/folders for authorized systems
  only.");

  script_xref(name:"URL", value:"http://pen-testing.sans.org/blog/pen-testing/2012/12/06/all-your-svn-are-belong-to-us");
  script_xref(name:"URL", value:"https://github.com/anantshri/svn-extractor");
  script_xref(name:"URL", value:"https://blog.skullsecurity.org/2012/using-git-clone-to-get-pwn3d");
  script_xref(name:"URL", value:"https://blog.netspi.com/dumping-git-data-from-misconfigured-web-servers/");
  script_xref(name:"URL", value:"http://resources.infosecinstitute.com/hacking-svn-git-and-mercurial/");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  script_timeout(600);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

# nb: /.svn/entries is already checked in gb_svn_entries_http.nasl
files = make_array( # Git:
                    #
                    # ref: refs/heads/master
                    "/.git/HEAD", "^ref: refs/",
                    "/.git/FETCH_HEAD", "^[a-f0-9]{40}\s+(not-for-merge\s+)?branch ",
                    "/.git/ORIG_HEAD", "^[a-f0-9]{40}$",
                    # 0000000000000000000000000000000000000000 464a47d28657dc9e53374be58b749734e7e268a1 <redacted> 1688388081 +0200 commit (initial): test
                    "/.git/logs/HEAD", "^[a-f0-9]{40} [a-f0-9]{40} ",
                    # [remote "origin"]
                    # [branch "master"]
                    # [core]
                    "/.git/config", "^\[(core|receive|(remote|branch) .+)\]$",
                    "/.git/info/refs", "^[a-f0-9]{40}\s+refs/",
                    # Unnamed repository; edit this file 'description' to name the repository.
                    "/.git/description", "^Unnamed repository",
                    # # git ls-files --others --exclude-from=.git/info/exclude
                    "/.git/info/exclude", "^# git ls-files",
                    # https://git-scm.com/docs/index-format
                    # nb: Includes additional binary info so no ".+" or similar is used
                    "/.git/index", "^DIRC",
                    #
                    # HG / Mercurial:
                    #
                    # https://www.mercurial-scm.org/wiki/MissingRequirement
                    "/.hg/requires", "^(revlogv1|store|fncache|shared|dotencode|parentdelta|generaldelta|sparse-revlog|revlog-compression-zstd)$",
                    # https://www.mercurial-scm.org/doc/hgrc.5.html
                    "/.hg/hgrc", "^(\[(paths|web|hooks|ui)\]$|# example repository config)",
                    "/.hg/branch", "^(default|production|stable|release)$",
                    "/.hg/undo.branch", "^(default|production|stable|release)$",
                    "/.hg/branch.cache", "^[a-f0-9]{40} [0-9a-zA-Z.-]+$",
                    "/.hg/branchheads.cache", "^[a-f0-9]{40} [0-9a-zA-Z.-]+$",
                    "/.hg/last-message.txt", "^no message$",
                    "/.hg/undo.desc", "^(push-response|pull|commit|serve|remote:ssh:[a-z0-9.]+)$",
                    #
                    # CVS:
                    #
                    # File contains an entry for the remote or local repository in a form like:
                    # [:method:][[[user][:password]@]hostname[:[port]]]/path
                    # http://commons.oreilly.com/wiki/index.php/Essential_CVS/CVS_Administration/Remote_Repositories
                    "/CVS/Root", "^:(local|ext|fork|server|gserver|kserver|pserver):[^\r\n]+/",
                    "/RCS/", '<a href="[^"]+,v"> ?[^,]+,v</a>',
                    # https://www.gnu.org/software/trans-coord/manual/cvs/html_node/Working-directory-storage.html
                    # e.g.
                    # D/name/filler1/filler2/filler3/filler4
                    # /name/revision/timestamp/options/tagdate
                    # nb: Different regexes are used here to make the second one a little bit more
                    # strict to avoid false positives
                    "/CVS/Entries", "^(D/[^/]+/[^/]*/[^/]*/[^/]*/|/[^/]+/[^/]+/[^/]+/[^/]+/.+)",
                    #
                    # Bazaar:
                    #
                    "/.bzr/README", "This is a Bazaar control directory.",
                    "/.bzr/branch-format", "Bazaar-NG meta directory",
                    #
                    # SVN:
                    #
                    "/.svn/dir-prop-base", "svn:ignore",
                    "/.svn/all-wcprops", "svn:wc:",
                    "/.svn/wc.db", "SQLite format",
                    #
                    # Looks like a 3rdparty tool for git/mercurial
                    #
                    "/.hg/sourcetreeconfig", "^((savedIncoming|lastUsedView|savedOutgoing|disablerecursiveoperations|autorefreshremotes)=[01]$|(remoteProjectLink[0-9]+\.(identifier|username|baseUrl|remoteName|type)|lastCheckedRemotes)=)",
                    "/.git/sourcetreeconfig", "^((savedIncoming|lastUsedView|savedOutgoing|disablerecursiveoperations|autorefreshremotes)=[01]$|(remoteProjectLink[0-9]+\.(identifier|username|baseUrl|remoteName|type)|lastCheckedRemotes)=)" );

report = "The following SCM files/folders were identified:";

port = http_get_port( default:80 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  foreach file( keys( files ) ) {

    url = dir + file;
    pattern = files[file];

    res = http_get_cache( port:port, item:url );

    # nb: If false positives are reported at some point in the future we might want to check for a
    # "Content-Type: text/html" and continue here if this is included.
    if( ! res || res !~ "^HTTP/1\.[01] 200" )
      continue;

    res = http_extract_body_from_response( data:res );
    res = chomp( res );
    if( ! res )
      continue;

    if( match = egrep( string:res, pattern:pattern, icase:FALSE ) ) {
      report += '\n\nMatch:      ' + chomp( match );
      report += '\nUsed regex: ' + pattern;
      report += '\nURL:        ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      VULN = TRUE;
    }
  }
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
